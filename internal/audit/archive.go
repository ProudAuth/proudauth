package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/proudauth/proudauth/internal/storage"
)

// ArchiveHeader is the first line of an archived batch file (AUD-008).
type ArchiveHeader struct {
	Record       string `json:"record"`
	BatchID      string `json:"batch_id"`
	Sequence     int64  `json:"sequence"`
	PreviousHash string `json:"previous_hash"`
	EventsDigest string `json:"events_digest"`
	BatchHash    string `json:"batch_hash"`
	Signature    string `json:"signature,omitempty"`
	SigningKID   string `json:"signing_kid,omitempty"`
	EventCount   int    `json:"event_count"`
	// ArchivedEvents is the number of event lines in the file: lower than
	// EventCount only when retention removed events before archiving.
	ArchivedEvents *int `json:"archived_events,omitempty"`
}

// errArchiveConflict reports a file that exists with different content.
var errArchiveConflict = errors.New("audit archive: file exists with different content")

// ArchiveBatches writes sealed batches after the last archived one to dir as
// write-once files (AUD-008): one NDJSON file per batch, a header line with
// the batch hash, chain link and signature, then every event as recorded.
// Files are created exclusively and read-only; an existing file is accepted
// only if it is byte-identical, so the archive never rewrites history. Point
// dir at storage the operator controls independently, ideally with
// retention locks (object lock, WORM volume).
//
// After a database restore, newly sealed batches can reuse sequence numbers
// the archive already holds with other content. The archive keeps that
// history and continues in a fork directory, fork-<sequence>-<batch id>,
// whose first batch links to the last common batch; onFork, when set, is told
// so the fork can be recorded.
func ArchiveBatches(ctx context.Context, db *storage.DB, dir string, max int) (int, error) {
	return ArchiveBatchesWith(ctx, db, dir, max, nil)
}

// ArchiveBatchesWith is ArchiveBatches with a fork callback.
func ArchiveBatchesWith(ctx context.Context, db *storage.DB, dir string, max int, onFork func(sequence int64, directory string)) (int, error) {
	var last int64
	var sub string
	if err := db.Pool.QueryRow(ctx, `SELECT last_sequence, directory FROM audit_archive_state`).Scan(&last, &sub); err != nil {
		return 0, err
	}
	rows, err := db.Pool.Query(ctx, `SELECT id, sequence_number, previous_hash, events_digest, batch_hash, coalesce(signature,''), coalesce(signing_kid,''),
		event_count FROM audit_batches WHERE sequence_number > $1 ORDER BY sequence_number LIMIT $2`, last, max)
	if err != nil {
		return 0, err
	}
	var batches []ArchiveHeader
	for rows.Next() {
		h := ArchiveHeader{Record: "batch"}
		if err := rows.Scan(&h.BatchID, &h.Sequence, &h.PreviousHash, &h.EventsDigest, &h.BatchHash, &h.Signature, &h.SigningKID, &h.EventCount); err != nil {
			rows.Close()
			return 0, err
		}
		batches = append(batches, h)
	}
	rows.Close()
	n := 0
	for _, h := range batches {
		var buf bytes.Buffer
		line, _ := json.Marshal(h)
		buf.Write(line)
		buf.WriteByte('\n')
		erows, err := db.Pool.Query(ctx, `SELECT seq, id, schema_version, type, occurred_at, coalesce(realm_id,''), coalesce(organization_id,''), actor_type, actor_id,
			coalesce(actor_session_id,''), coalesce(subject_type,''), coalesce(subject_id,''), coalesce(target_type,''), coalesce(target_id,''), outcome,
			coalesce(reason_code,''), coalesce(request_id,''), coalesce(client_id,''), coalesce(session_id,''), coalesce(grant_id,''),
			coalesce(impersonation_grant_id,''), source, coalesce(reporting_service,''), coalesce(ip_context,''), metadata, category, content_hash,
			coalesce(batch_id,'') FROM audit_events WHERE batch_id=$1 ORDER BY seq`, h.BatchID)
		if err != nil {
			return n, err
		}
		count := 0
		for erows.Next() {
			ev, _, err := scanEvent(erows)
			if err != nil {
				erows.Close()
				return n, err
			}
			l, _ := json.Marshal(ev)
			buf.Write(l)
			buf.WriteByte('\n')
			count++
		}
		erows.Close()
		// When retention removed events before archiving (only possible for
		// batches pruned before the archive was configured), the header keeps
		// the sealed count and records how many events the file holds.
		if count != h.EventCount {
			c := count
			h.ArchivedEvents = &c
			var b bytes.Buffer
			line, _ := json.Marshal(h)
			b.Write(line)
			b.WriteByte('\n')
			b.Write(buf.Bytes()[bytes.IndexByte(buf.Bytes(), '\n')+1:])
			buf = b
		}
		file := fmt.Sprintf("batch-%012d.ndjson", h.Sequence)
		err = writeOnce(filepath.Join(dir, sub, file), buf.Bytes())
		if errors.Is(err, errArchiveConflict) {
			sub = fmt.Sprintf("fork-%012d-%s", h.Sequence, h.BatchID)
			if err = os.MkdirAll(filepath.Join(dir, sub), 0o750); err == nil {
				err = writeOnce(filepath.Join(dir, sub, file), buf.Bytes())
			}
			if err == nil && onFork != nil {
				onFork(h.Sequence, sub)
			}
		}
		if err != nil {
			return n, err
		}
		if _, err := db.Pool.Exec(ctx, `UPDATE audit_archive_state SET last_sequence=$1, directory=$2, updated_at=now()`, h.Sequence, sub); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func writeOnce(name string, data []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o440)
	if errors.Is(err, os.ErrExist) {
		cur, rerr := os.ReadFile(name)
		if rerr != nil {
			return rerr
		}
		if !bytes.Equal(cur, data) {
			return fmt.Errorf("%w: %s", errArchiveConflict, filepath.Base(name))
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// VerifyArchive checks an archive directory independently of the database
// (AUD-008): event content hashes, batch digests, batch hashes, the hash chain
// and sequence continuity across files and, when verify is set, batch
// signatures. Events can be missing from a file only for batches pruned
// before the archive was configured, which form a leading run: a short file
// after a complete one, or fewer lines than the header records, is reported.
// Fork directories written after a database restore are verified as chains
// that branch from the main archive. The newest batches can only be compared
// with the database (identity-cli verify-audit); the report gives the range.
func VerifyArchive(dir string, verify func(kid, hash, sig string) bool) (*VerificationReport, error) {
	rep := &VerificationReport{Problems: []string{}}
	main := map[int64]string{}
	if err := verifyArchiveChain(dir, "", verify, rep, main, nil); err != nil {
		return nil, err
	}
	forks, err := filepath.Glob(filepath.Join(dir, "fork-*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(forks)
	for _, f := range forks {
		rep.Forks = append(rep.Forks, filepath.Base(f))
		if err := verifyArchiveChain(f, filepath.Base(f)+"/", verify, rep, nil, main); err != nil {
			return nil, err
		}
	}
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

func verifyArchiveChain(dir, label string, verify func(kid, hash, sig string) bool, rep *VerificationReport, record, parent map[int64]string) error {
	names, err := filepath.Glob(filepath.Join(dir, "batch-*.ndjson"))
	if err != nil {
		return err
	}
	sort.Strings(names)
	prev, prevSeq := "", int64(0)
	complete := false
	for i, name := range names {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		var h ArchiveHeader
		digest := sha256.New()
		events := 0
		first := true
		for sc.Scan() {
			if first {
				first = false
				if err := json.Unmarshal(sc.Bytes(), &h); err != nil || h.Record != "batch" {
					rep.Problems = append(rep.Problems, label+filepath.Base(name)+": missing batch header")
					break
				}
				continue
			}
			var ev Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				rep.Problems = append(rep.Problems, label+filepath.Base(name)+": unreadable event")
				continue
			}
			events++
			if ContentHash(ev) != ev.ContentHash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s%s: event %s content hash mismatch", label, filepath.Base(name), ev.ID))
			}
			digest.Write([]byte(ev.ID + ":" + ev.ContentHash + "\n"))
		}
		f.Close()
		rep.Batches++
		rep.Events += events
		switch {
		case i == 0 && parent != nil:
			// A fork's first batch links to the last batch both histories share.
			if want, ok := parent[h.Sequence-1]; ok && want != h.PreviousHash {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d does not link to archived batch %d", label, h.Sequence, h.Sequence-1))
			}
		case i == 0 && h.Sequence == 1 && h.PreviousHash != strings.Repeat("0", 64):
			rep.Problems = append(rep.Problems, label+"batch 1 does not start the chain")
		case i > 0 && h.Sequence != prevSeq+1:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatches %d to %d are missing from the archive", label, prevSeq+1, h.Sequence-1))
		case i > 0 && h.PreviousHash != prev:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d does not link to the previous archived batch", label, h.Sequence))
		}
		if i == 0 && record != nil {
			rep.FirstSequence = h.Sequence
		}
		switch {
		case h.ArchivedEvents != nil && events != *h.ArchivedEvents:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d: %d events in the file, header records %d", label, h.Sequence, events, *h.ArchivedEvents))
		case events == h.EventCount:
			complete = true
			if hex.EncodeToString(digest.Sum(nil)) != h.EventsDigest {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d events digest mismatch", label, h.Sequence))
			}
		case h.ArchivedEvents == nil || complete:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d: events missing from the archived file", label, h.Sequence))
		default:
			rep.Pruned++
		}
		bh := sha256.Sum256([]byte(h.PreviousHash + "|" + h.EventsDigest + "|" + fmt.Sprint(h.Sequence)))
		if hex.EncodeToString(bh[:]) != h.BatchHash {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d hash mismatch", label, h.Sequence))
		}
		if verify != nil {
			if !verify(h.SigningKID, h.BatchHash, h.Signature) {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%sbatch %d signature missing or invalid", label, h.Sequence))
			} else if h.Signature != "" {
				rep.Signed++
			}
		}
		if record != nil {
			record[h.Sequence] = h.BatchHash
			rep.LastSequence = h.Sequence
		}
		prev, prevSeq = h.BatchHash, h.Sequence
	}
	return nil
}
