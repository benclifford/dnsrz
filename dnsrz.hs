{-# LANGUAGE ScopedTypeVariables #-}

import Control.Applicative
import Data.IP
import Data.List
import Data.Maybe
import System.Environment
import System.IO
import System.Process
import qualified Text.ParserCombinators.Parsec as PS

netprefix = "200108b0007c0001"

main = do
  hPutStrLn stderr "dnsrz (c)2012 CQX Limited"
  zones <- getArgs
  mapM_ processZone zones

processZone z = do
  let (zone, _:server) = span (\e -> e /= '@') z
  hPutStrLn stderr $ "forward zone is " ++ zone
  hPutStrLn stderr $ "server is " ++ server
  fz <- axfr zone server
  let (Right aaaalist) = parseAAAAs fz
  let l2 = catMaybes aaaalist
  let l3 = map (\(a,b) -> (a, expandipv6 b)) l2
  let l4 = map (\(name, Right addr) -> (name, addr)) l3
  let l5 = filter (\(name, addr) -> netprefix `isPrefixOf` addr) l4
  mapM_ (\(name, addr) -> putStrLn $ (ptrFormat $ drop (length netprefix) addr) ++ " PTR " ++ name) l5

ptrFormat s = intersperse '.' $ reverse s

expandipv6 addr = PS.parse parseIPv6 addr addr

manyOf l = PS.many $ PS.oneOf l

fleshout :: String -> String
fleshout s = let
    pad = 4 - length s
    padding = take pad $ repeat '0'
  in padding ++ s

parseIPv6 = do
  segs <- seg `PS.sepBy` (PS.char ':')
  -- segs will be ipv6 segments. one might be an empty one, if abbreviated
  -- notation is used.
  let
   a =
    if ("" `elem` segs) then
      let
          (fore, _:aft) = span (\e -> e /= "") segs
          pad = 8 - (length fore) - (length aft)
          padding = take pad $ repeat "0000"
        in (map fleshout fore) ++ padding ++ (map fleshout aft)
    else
      -- not abbreviated path
      map fleshout segs
  return $ concat a

seg = do
  s <- manyOf "0123456789abcdefABCDEF"
  return s

axfr (zone :: String) (server :: String) = do
  readProcess "dig" ["@" ++ server,
                     "-t", "axfr",
                     "+nottlid", "+nocl",
                     zone] ""
-- dig @dildano.hawaga.org.uk -t axfr hawaga.org.uk +nottlid +nocl 

parseAAAAs digOutput = PS.parse aaaaParser "(unknown-dig-output)" digOutput

aaaaParser = PS.many rrline

rrline = emptyLine <|> commentLine <|> contentLine

emptyLine = PS.char '\n' >> return Nothing

commentLine = do
  PS.char ';'
  PS.many (PS.noneOf "\n")
  PS.char '\n'
  return Nothing

contentLine = do
  domain <- PS.many $ PS.noneOf " \t"
  PS.many $ PS.oneOf " \t"
  rrtype <- PS.many $ PS.noneOf " \t"
  PS.many $ PS.oneOf " \t"
  rest <- many (PS.noneOf "\n")
  PS.char '\n'
  return $ if rrtype == "AAAA" then Just (domain,rest) else Nothing

