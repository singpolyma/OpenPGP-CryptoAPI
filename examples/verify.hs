import System (getArgs)

import Data.Binary

import qualified Data.OpenPGP as OpenPGP ()
import qualified Data.OpenPGP.CryptoAPI as OpenPGP

main :: IO ()
main = do
	argv <- getArgs
	keys <- decodeFile (argv !! 0)
	message <- decodeFile (argv !! 1)
	-- Just verify first signature
	print $ OpenPGP.verify keys message 0
