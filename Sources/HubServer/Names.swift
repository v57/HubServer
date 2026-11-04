import Foundation

// Device names (protocol.md section 13): what counts as the same name, and the name a device gets. Only the hub needs
// this, so it lives in hub-server and HubServer alone; `names` in vectors.json holds both to one result.

/// Letters that look like another one once case and marks are gone: the letter, then its lookalikes. Not all of Unicode's
/// confusables: the ones that pass for Latin letters and digits in Cyrillic, Greek, Armenian, Cherokee, Hebrew and
/// Arabic. A false match only costs a device a suffix.
private let lookalikes: [(String, String)] = [
  ("a", "аɑαꭺ⍺"),
  ("b", "вьβƅ"),
  ("c", "сꮯ"),
  ("d", "ԁꭰđ"),
  ("e", "еεєҽꭼ"),
  ("f", "ƒғ"),
  ("g", "ɡցԍꮐ"),
  ("h", "һнհꮋħ"),
  ("j", "јϳ"),
  ("k", "кκꮶĸ"),
  ("l", "iіıιɩӏǀ|ꮮ\u{05D5}\u{0627}\u{0661}\u{06F1}ꓲł1"),
  ("m", "мꮇϻ"),
  ("n", "пηո"),
  ("o", "оοσςօᴏ\u{09E6}\u{0966}ⲟø0"),
  ("p", "рρⲣꮲ"),
  ("q", "ԛզ"),
  ("r", "гꭱɾ"),
  ("s", "ѕꮪƽ"),
  ("t", "тτꭲŧ"),
  ("u", "υսʋ"),
  ("v", "νѵꮩᴠ"),
  ("w", "ԝѡωꮃᴡ"),
  ("x", "хχ"),
  ("y", "уγүꭹʏ"),
  ("z", "ζᴢꮓ"),
  ("3", "з"),
  ("ss", "ß"),
  ("ae", "æ"),
  ("oe", "œ")
]
private let lookalikeMap: [Unicode.Scalar: String] = {
  var map: [Unicode.Scalar: String] = [:]
  for (letter, others) in lookalikes {
    for other in others.unicodeScalars { map[other] = letter }
  }
  return map
}()

/// Capitals whose lowercase form looks like a different letter
private let capitalLookalikes: [Unicode.Scalar: String] = ["\u{0397}": "h", "\u{039D}": "n", "\u{03A5}": "y"]

/// Pairs of letters that read as one letter
private let letterPairs = [("rn", "m"), ("vv", "w"), ("cl", "d")]

private func isIgnored(_ scalar: Unicode.Scalar) -> Bool {
  if scalar.properties.isDefaultIgnorableCodePoint { return true }
  switch scalar.properties.generalCategory {
  case .nonspacingMark, .enclosingMark,
    .control, .format, .surrogate, .privateUse, .unassigned,
    .spaceSeparator, .lineSeparator, .paragraphSeparator,
    .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation, .initialPunctuation, .finalPunctuation, .otherPunctuation:
    return true
  default:
    return false
  }
}

/// What names are compared by: no case, spaces, punctuation, marks or invisible characters, lookalikes as one letter
func normalizeName(_ name: String) -> String {
  // Unicode's decomposition reads these as sigma, which looks like nothing they do
  var before = String.UnicodeScalarView()
  for scalar in name.unicodeScalars {
    before.append(scalar == "\u{03F2}" || scalar == "\u{03F9}" ? "c" : scalar)
  }
  var letters = ""
  for scalar in String(before).decomposedStringWithCompatibilityMapping.unicodeScalars where !isIgnored(scalar) {
    if let capital = capitalLookalikes[scalar] { letters += capital } else { letters.unicodeScalars.append(scalar) }
  }
  var text = ""
  for scalar in letters.lowercased().unicodeScalars {
    if let letter = lookalikeMap[scalar] { text += letter } else { text.unicodeScalars.append(scalar) }
  }
  for (pair, letter) in letterPairs { text = text.replacingOccurrences(of: pair, with: letter, options: .literal) }
  return text
}

/// Longest device name in bytes
private let maxNameBytes = 64

/// What JavaScript's trim takes away, so both hubs clean a name alike
private func isSpace(_ scalar: Unicode.Scalar) -> Bool {
  if scalar.properties.generalCategory == .spaceSeparator { return true }
  switch scalar.value {
  case 0x09...0x0D, 0x2028, 0x2029, 0xFEFF: return true
  default: return false
  }
}

private func trimmedEnd(_ scalars: [Unicode.Scalar]) -> [Unicode.Scalar] {
  var end = scalars.count
  while end > 0, isSpace(scalars[end - 1]) { end -= 1 }
  return Array(scalars[..<end])
}

private func text(_ scalars: [Unicode.Scalar]) -> String {
  var view = String.UnicodeScalarView()
  view.append(contentsOf: scalars)
  return String(view)
}

/// The first code points of `name` that fit in `bytes`, with no space left at the end
private func fit(_ name: [Unicode.Scalar], _ bytes: Int) -> [Unicode.Scalar] {
  var used = 0
  var kept: [Unicode.Scalar] = []
  for scalar in name {
    used += UTF8.width(scalar)
    if used > bytes { break }
    kept.append(scalar)
  }
  return trimmedEnd(kept)
}

/// Control characters and the invisible ones that reorder text
private func isRemovedFromNames(_ scalar: Unicode.Scalar) -> Bool {
  if scalar.properties.generalCategory == .control { return true }
  switch scalar.value {
  case 0x2028, 0x2029, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x061C: return true
  default: return false
  }
}

/// A name as a device or owner wrote it, ready to show: without control characters and the invisible ones that reorder
/// text, trimmed, at most 64 bytes. A name with nothing left to compare is `Device`.
func cleanName(_ name: String) -> String {
  var scalars = trimmedEnd(name.unicodeScalars.filter { !isRemovedFromNames($0) })
  scalars = Array(scalars.drop(while: isSpace))
  let clean = text(fit(scalars, maxNameBytes))
  return normalizeName(clean).isEmpty ? "Device" : clean
}

/// The name a device asking for `asked` gets: that one if nobody holds it, else `<name>-2`, `-3` and so on
func freeName(_ asked: String, held: (String) -> Bool) -> String {
  let name = cleanName(asked)
  if !held(normalizeName(name)) { return name }
  let scalars = Array(name.unicodeScalars)
  var number = 2
  while true {
    let suffix = "-\(number)"
    let candidate = text(fit(scalars, maxNameBytes - suffix.utf8.count)) + suffix
    if !held(normalizeName(candidate)) { return candidate }
    number += 1
  }
}
