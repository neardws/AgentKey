import Foundation

public struct PasswordGenerator: Sendable {
    public struct Options: Sendable {
        public var length = 24
        public var lowercase = true, uppercase = true, digits = true, symbols = true
        public var excludeAmbiguous = true
        public init(length: Int = 24) { self.length = length }
    }

    public static let lower = "abcdefghijklmnopqrstuvwxyz", upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                      digitSet = "0123456789", symbolSet = "!@#$%^&*()-_=+[]{};:,.?/~"
    static let ambiguous = Set("Il1O0o")

    public static func generate(_ o: Options = Options()) -> String {
        var g = SystemRandomNumberGenerator()
        var classes: [[Character]] = []
        if o.lowercase { classes.append(Array(lower)) }
        if o.uppercase { classes.append(Array(upper)) }
        if o.digits { classes.append(Array(digitSet)) }
        if o.symbols { classes.append(Array(symbolSet)) }
        if o.excludeAmbiguous { classes = classes.map { $0.filter { !ambiguous.contains($0) } } }
        precondition(!classes.isEmpty && o.length >= classes.count, "invalid options")
        let all = classes.flatMap { $0 }
        // one from each class, rest from the union, then Fisher–Yates shuffle (uniform, CSPRNG)
        var chars = classes.map { $0.randomElement(using: &g)! }
        while chars.count < o.length { chars.append(all.randomElement(using: &g)!) }
        chars.shuffle(using: &g)
        return String(chars)
    }

    /// Diceware-style passphrase from a small embedded list (replace with EFF large list for production).
    public static func passphrase(words count: Int = 5, separator: String = "-") -> String {
        var g = SystemRandomNumberGenerator()
        return (0..<count).map { _ in wordlist.randomElement(using: &g)! }.joined(separator: separator)
    }
    // TODO: ship EFF large wordlist (7776 words, 12.9 bits/word). This list is a placeholder.
    static let wordlist = ["acorn","amber","anchor","apple","arrow","aspen","atlas","badge","banjo","basil","beacon","birch","bison","blaze","bloom","breeze","brook","cabin","cactus","canyon","cedar","chalk","cider","cloud","cobalt","comet","coral","crane","delta","denim","dune","eagle","ember","fable","falcon","fern","fjord","flint","forge","fossil","garnet","glacier","granite","harbor","hazel","heron","indigo","iris","ivory","jade","jasper","juniper","kayak","kelp","lagoon","lantern","lemon","lilac","lotus","lunar","maple","marble","meadow","mint","nectar","nimbus","nova","oak","olive","onyx","orbit","otter","pebble","pepper","pine","pixel","plume","prism","quartz","quill","raven","reef","ridge","river","saffron","sage","sierra","slate","sparrow","spruce","summit","tango","thistle","tide","topaz","tundra","umber","velvet","violet","walnut","willow","yarrow","zephyr"]
}
