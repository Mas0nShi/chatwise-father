# Chatwise Father

Chatwise's father

It's support for 🍎 macOS/(arm64, x86_64) and 🪟 Windows(x86_64)

> [!WARNING]
> This tool is only for educational purposes. I am not responsible for any illegal use of this tool.

## Install

```bash
git clone https://github.com/Mas0nShi/chatwise-father.git
cd chatwise-father
cargo build --release
```

## Usage

```bash
./chatwise-patcher -i <input_file> -o <output_file>
```

### macOS

```bash
chatwise-patcher -i /Applications/ChatWise.app/Contents/MacOS/chatwise -o /tmp/chatwise
mv /tmp/chatwise /Applications/ChatWise.app/Contents/MacOS/chatwise
chmod +x /Applications/ChatWise.app/Contents/MacOS/chatwise
sudo codesign --force --deep --sign - /Applications/ChatWise.app/Contents/MacOS/chatwise
# optional: login with token in first install
open "chatwise://login-success?token=[REDACTED_TOKEN]"
```

### Windows

```powershell
chatwise-patcher -i %USERPROFILE%\AppData\Local\ChatWise\chatwise.exe -o %TEMP%\chatwise.exe
move /Y %TEMP%\chatwise.exe %USERPROFILE%\AppData\Local\ChatWise\chatwise.exe
# optional: login with token in first install
start "" "chatwise://login-success?token=[REDACTED_TOKEN]"
```
