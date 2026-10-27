import Foundation

/// feat/nc-sudoku-udp: the Sudoku UoT association (Shared/NativeCore/NCSudokuUoT.swift) is a data plane UDP
/// session as is — NCDataPlane.openUDP's `sudoku` case creates one per stack UDP session.
extension NCSudokuUDPSession: NCUDPSession {}
