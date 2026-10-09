import Foundation
import CoreImage
import CoreImage.CIFilterBuiltins
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count >= 2 else {
    fputs("usage: keywarden-qr <output.png> [--terminal] < payload\n", stderr)
    exit(2)
}

guard let payload = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8), !payload.isEmpty else { exit(2) }
let output = CommandLine.arguments[1]
let renderTerminal = CommandLine.arguments.dropFirst(2).contains("--terminal")
let filter = CIFilter.qrCodeGenerator()
filter.message = Data(payload.utf8)
// Medium correction keeps the modules large enough for a phone camera.
filter.correctionLevel = "M"

guard let image = filter.outputImage else { fatalError("Could not create QR image") }
let scaled = image.transformed(by: CGAffineTransform(scaleX: 32, y: 32))
let context = CIContext()
guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else {
    fatalError("Could not render QR image")
}

let destinationURL = URL(fileURLWithPath: output) as CFURL
guard let destination = CGImageDestinationCreateWithURL(destinationURL, UTType.png.identifier as CFString, 1, nil) else {
    fatalError("Could not open output file")
}
CGImageDestinationAddImage(destination, cgImage, nil)
guard CGImageDestinationFinalize(destination) else { fatalError("Could not write QR image") }

if renderTerminal {
    guard let terminalImage = context.createCGImage(image, from: image.extent),
          let imageData = terminalImage.dataProvider?.data as Data? else {
        fatalError("Could not read QR image for terminal output")
    }
    let bytesPerPixel = max(1, terminalImage.bitsPerPixel / 8)
    let bytesPerRow = terminalImage.bytesPerRow
    let width = terminalImage.width
    let height = terminalImage.height
    func isDark(_ x: Int, _ y: Int) -> Bool {
        let offset = y * bytesPerRow + x * bytesPerPixel
        return imageData[offset] < 128
    }
    for y in stride(from: 0, to: height, by: 2) {
        var row = ""
        for x in 0..<width {
            let top = isDark(x, y)
            let bottom = y + 1 < height && isDark(x, y + 1)
            row.append(top ? (bottom ? "█" : "▀") : (bottom ? "▄" : " "))
        }
        print(row)
    }
}
