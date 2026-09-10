// The names the clients called before the rename; each is the gossveil name.
export { GossveilError as SignalError } from './core'
export {
  WhisperMessage as SignalMessage,
  PreKeyMessage as PreKeySignalMessage,
  InMemoryProtocolStore as InMemorySignalProtocolStore,
  sessionEncrypt as signalEncrypt,
  sessionDecrypt as signalDecrypt,
  sessionDecryptPreKey as signalDecryptPreKey,
} from './api'
