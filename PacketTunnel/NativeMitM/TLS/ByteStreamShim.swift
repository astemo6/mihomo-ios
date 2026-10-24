// feat/s2-tls: PROVISIONAL copy of the stage-2 shared contract's ByteStream (work/native-s2-lanes.md). The `wire`
// lane owns the real one in PacketTunnel/NativeMitM/S2Contract.swift; delete this file at integration (if the
// signatures differ, adapt TLSByteStream's three methods — nothing else in TLS/ depends on them).

import Foundation

protocol ByteStream: AnyObject {
    /// Delivers between `min` and `max` bytes (fewer only at end of stream). `isComplete` = the peer closed its
    /// write side; `error` != nil = the stream is dead.
    func read(min: Int, max: Int, completion: @escaping (_ data: Data?, _ isComplete: Bool, _ error: Error?) -> Void)
    func write(_ data: Data, completion: @escaping (_ error: Error?) -> Void)
    func close()
}
