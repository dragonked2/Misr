a


# Misr: The Ultimate Vulnerability Scanner

![Misr](https://github.com/dragonked2/Misr/assets/66541902/b83f3c98-1946-4d2d-86c7-da101a280000)

Welcome to Misr, the ultimate tool for hunting down vulnerabilities in web applications! Whether you're a seasoned bug bounty hunter or just getting started in the world of cybersecurity, this script will help you identify potential vulnerabilities with ease.

## About the Author

Misr is created by [Ali Essam](https://github.com/dragonked2), a passionate cybersecurity enthusiast with years of experience in penetration testing and bug bounty hunting. Ali's mission is to make the web a safer place for everyone by empowering security professionals and ethical hackers with powerful tools like Misr.

## Features

- **Powerful Vulnerability Detection**: Misr utilizes advanced techniques to scan web applications for common vulnerabilities like SQL injection, XSS, RCE, LFI, and SSRF.
  
- **Content-Type Filtering**: Reduce false positives by filtering responses based on Content-Type before confirming vulnerabilities.

- **Subdomain Enumeration**: Easily extract subdomains from a given domain to expand your target list.

- **Secrets Detection**: Find sensitive information like passwords, API keys, and email addresses hidden within web pages.

- **User-Friendly Interface**: With a sleek command-line interface and colorful progress bars, Misr makes vulnerability scanning both efficient and enjoyable.

## How to Use

1. Clone the repository:
   ```
   git clone https://github.com/dragonked2/misr.git
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   download https://github.com/projectdiscovery/httpx
   download https://github.com/projectdiscovery/subfinder/
   keep them in same directory of the tool
   ```

3. Run the script:
   ```
   python misr.py
   ```

4. Follow the on-screen prompts to choose between scanning a single website or extracting subdomains from a domain.

5. Sit back and let Misr do its magic! Once the scan is complete, you'll find detailed reports of vulnerabilities and secrets in the specified output files.

## Contributions

Misr is an open-source project, and contributions are welcome! If you have any ideas for improvements or new features, feel free to open an issue or submit a pull request.

Let's work together to make the web a safer place for everyone!

---
