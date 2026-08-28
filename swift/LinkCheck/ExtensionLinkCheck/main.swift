// The positive half of the link check: an executable that links ShoesTunnel
// with the engine live, so `nm` must find shoes_* here. Without it the host
// assertion could pass against an empty binary.
import ShoesTunnel

let engine = ShoesEngine.shared
print("shoes \(engine.version)")
