English | [Русский](README.ru.md)

# Executable Architecture Detector

Detect the CPU architecture of an executable file using **frequency byte-signature analysis** and machine learning — no need to rely solely on header parsing (PE/ELF/Mach-O), which can fail on packed, obfuscated, or corrupted binaries.

## How It Works

The tool analyzes the frequency distribution of byte patterns within the executable's code section, treating it as a signature of the underlying CPU instruction set. These frequency signatures are compared against a set of **predefined reference signatures** (stored in the `Signatures/` folder) using three independent machine learning classifiers:

- **Random Forest**
- **K-Nearest Neighbors (KNN)**
- **Logistic Regression**

Each model votes on the most likely architecture, giving you a consensus-based prediction instead of relying on a single heuristic.

This approach is especially useful when:
- The binary is packed or obfuscated
- Standard section parsing (e.g. locating a `.text`/code section) fails
- You want a secondary, independent check alongside traditional header-based detection

## Features

- 🔍 Automatic detection of executable architecture via ML ensemble
- 🧬 Byte-frequency signature-based analysis (no reliance on file headers alone)
- 🛠 Advanced mode for manually specifying the byte range of code when automatic section parsing isn't possible
- 📊 Built-in tooling to generate your own "gold standard" reference signatures
- 📝 Configurable output file and verbose logging

## Installation

```bash
git clone https://github.com/yourusername/your-repo-name.git
cd your-repo-name
pip install -r requirements.txt
```

> Update the clone URL and requirements above to match your actual repository setup.

## Usage

```bash
python main.py <filename> [options]
```

### Positional Arguments

| Argument   | Description                       |
|------------|------------------------------------|
| `filename` | Path to the executable file to analyze |

### Options

| Flag | Long form | Description |
|------|-----------|-------------|
| `-d` | `--detect` | Try to detect the architecture using all 3 ML algorithms |
| `-a` | `--advanced` | Advanced mode — manually specify the byte range where ASM instructions are located. Useful when the file is packed and the code section can't be parsed automatically |
| | `--range` | Byte range to analyze in advanced mode (used together with `-a`) |
| `-g` | `--gold` | Generate a `Signatures/` folder containing "gold" reference graphs/signatures for all supported architectures |
| `-o` | `--output` | File to write results to (default: `res.txt`) |
| `-v` | `--verbose` | Enable verbose output |

### Examples

Detect architecture automatically:
```bash
python main.py sample.exe -d
```

Detect architecture with a custom output file and verbose logging:
```bash
python main.py sample.exe -d -o results.txt -v
```

Advanced mode — manually specify byte range for a packed binary:
```bash
python main.py packed_sample.exe -a --range 0x1000 0x4000 -d
```

Regenerate gold-standard reference signatures:
```bash
python main.py --gold
```

## Project Structure

```
.
├── Signatures/        # Predefined byte-frequency signatures per architecture
├── Tests/             # Binaries to test program works properly
├── main.py            # CLI entry point (argparse-based interface)
├── requirements.txt    # Python dependencies
└── README.md
```

## Supported Architectures

> List the architectures your signatures currently support, e.g.:
- x86 (32-bit)
- x86-64
- ARM
- ARM64
- MIPS
- etc...

## Roadmap / Ideas

- [ ] Confidence scores per ML model in the output report
- [ ] Optional graphical/plot output of frequency signatures
- [ ] Make other ML ensemble methods
- [ ] Implement automatic parsing of packed files

## Contributing

Contributions, bug reports, and suggestions are welcome! Feel free to open an issue or submit a pull request.
