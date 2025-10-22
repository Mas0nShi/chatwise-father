# Chatwise Father

Chatwise's father

> [!IMPORTANT]
> **This project is a technical proof-of-concept for reverse engineering, not a one-click cracking tool.**
> 
> **simply patching the client will not unlock any pro features.**
> 
> The goal of this repository is to share technical insights, not to encourage piracy or harm the original developers. Please support them by purchasing a legitimate license.
>
> **本项目是一个关于逆向工程的技术验证，并非一个即用的“破解工具”。**
> 
> 仅使用本工具进行修补，**你不会获得任何破解效果**。
> 
> 创建此项目的目的是分享逆向工程的思路和过程，而非鼓励盗版或损害原作者的利益。请通过购买正版来支持开发者。
---

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
# 1. replace automatically
./chatwise-father
# 2. manually
./chatwise-father -i <input_file> -o <output_file>
```

### macOS manually

```bash
chatwise-father -i /Applications/ChatWise.app/Contents/MacOS/chatwise -o /tmp/chatwise
mv /tmp/chatwise /Applications/ChatWise.app/Contents/MacOS/chatwise
chmod +x /Applications/ChatWise.app/Contents/MacOS/chatwise
sudo codesign --force --deep --sign - /Applications/ChatWise.app/Contents/MacOS/chatwise
# optional: login with token in first install
open "chatwise://login-success?token=[REDACTED_TOKEN]"
```

### Windows manually

```powershell
chatwise-father -i %USERPROFILE%\AppData\Local\ChatWise\chatwise.exe -o %TEMP%\chatwise.exe
move /Y %TEMP%\chatwise.exe %USERPROFILE%\AppData\Local\ChatWise\chatwise.exe
# optional: login with token in first install
start "" "chatwise://login-success?token=[REDACTED_TOKEN]"
```
