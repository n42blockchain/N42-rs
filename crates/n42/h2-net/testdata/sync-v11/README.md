# N42 sync v1.1 wire vectors (gov5 reference)

Request/response vectors for the v1.1 sync protocols of N42-SYNC-SPEC.md:
bodies_by_range/2 (§5.1), commit_qc/1 (§5.2), qmdb_status/1,
qmdb_manifest/1, qmdb_twigs/1 and code_by_hash/1 (§5.3), with the §3
framing. Each file holds one protocol; each case has the decoded request
fields, the request payload and wire, the full response wire and its chunks
(result code, context bytes, payload, decoded END trailer or error message).

They are produced by gov5's servers (internal/sync/v11) over a deterministic
profile-1 chain and are reproducible from the gov5 branch feat/p1-sync-v11:

    N42_SYNC_V11_VECTORS_OUT=<dir> go test -tags nosqlite,noboltdb ./internal/ -run TestSyncV11Vectors

The same test checks them against internal/testdata/sync-v11 (golden).

Covered: SUCCESS, 0x01 INVALID_REQUEST, 0x03 RESOURCE_UNAVAILABLE, END
reasons 0 COMPLETE, 1 BYTE_BUDGET, 3 CANONICAL_END, 4 NOT_AVAILABLE, an
empty range (zero chunks), HEADERS_ONLY, BITS_ONLY, from_slot, hollow twigs,
LIVE (kind 1), LIVE_P (kind 4), DEAD (kind 2) and HOLLOW (kind 3) records,
and a manifest range proof. 0x04 RATE_LIMITED is the error chunk
0x04 || framed("1000") (retry_after_ms) and has no separate case.

## sha256

    27d5edfc766de64d87c1dc0a5d16ce34624ca91407fb3f2595a6f54ad60217d6  bodies_by_range_2.json
    86c536b055205beb7b6f153e967209e90a14b8dab0efbf9b3c4ddde37930dc0d  code_by_hash_1.json
    bf1ab9a872868730a809b13b2a19c6d8c5a56d063dc2d4a094a759b8108d1fe9  commit_qc_1.json
    c793ecb4a8abe23b60d4eb629432e4f8c65cab9acccf1bdc0e0dece925eb23c9  qmdb_manifest_1.json
    ccf972a2013d350f63700eb2fc1ba87f07d97a94f5e54c7a08055ceb848d2181  qmdb_status_1.json
    273a46e42a6fe38209f347335b87b7fb34214e555abacf2930f21f51433762a0  qmdb_twigs_1.json
