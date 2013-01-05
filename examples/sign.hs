import System.Environment (getArgs)
import System.Time (getClockTime, ClockTime(..))

import Data.Binary
import Crypto.Random

import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.CryptoAPI as OpenPGP
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ

main :: IO ()
main = do
	[path] <- getArgs
	time <- getClockTime
	rng <- newGenIO :: IO SystemRandom
	let TOD t _ = time
	keys <- decodeFile path
	let dataPacket = OpenPGP.LiteralDataPacket 'u' "t.txt"
			(fromIntegral t) (LZ.fromString "This is a message.")
	let (OpenPGP.DataSignature _ [sig], _) =
		OpenPGP.sign keys (OpenPGP.DataSignature dataPacket [])
			OpenPGP.SHA256 [] (fromIntegral t) rng
	let message = OpenPGP.Message [sig, dataPacket]
	LZ.putStr $ encode message
