# Secure API Scanner

A simple Python tool that checks:
- HTTPS usage
- TLS support
- common open ports
- security headers
- basic API response issues

## Files
- `scanner.py`
- `requirements.txt`
- `README.md`

## Run

### 1. Install Python packages
```bash
pip install -r requirements.txt
```

### 2. Run the scanner
```bash
python scanner.py https://api.github.com --json-out report.json
```

## Take screenshots
1. Screenshot the terminal after running the scanner
2. Screenshot the generated `report.json` file
3. Screenshot your GitHub repo after upload

## Create GitHub repo

### 1. Initialize git
```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
```

### 2. Create a new empty GitHub repo
Example name: `secure-api-scanner`

### 3. Connect and push
```bash
git remote add origin https://github.com/YOUR_USERNAME/secure-api-scanner.git
git push -u origin main
```

## Share repo
Copy the browser URL of your GitHub repository and submit that link.
