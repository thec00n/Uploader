# Uploader

The Burp extension verifies if file uploads are vulnerable to directory traversal vulnerabilities. It further checks if  files can be uploaded into the web directory of the application. This should help speed up testing for file upload vulnerabilities and be the basis for further testing such as uploading files that can be used to execute dynamic code. 

## Installation 
* Load JRuby (tested with 1.7) 
* Load `uploader.rb`
* Load [burp-suite-error-message-checks](https://github.com/augustd/burp-suite-error-message-checks)
* Active Scan run triggers `Uploader`

## Module 1 
The module assumes that the upload path is somewhere in the web directory and attempts file uploads based on directory traversal. It considers the Burp sitemap to find writeable directories.  

## Module 2 
The module assumes that the upload path is somewhere outside of the web directory. In order to find the web root it does basic fuzzing for the file upload to trigger an error message disclosing the absolute path of the web directory. Additionally it queries all findings from the extension burp-suite-error-message-checks to again find the absolute path of the web directory and to find writeable directories that are accessible. 

## Clean Up
The extension is fairly aggressive in terms of trying to write files onto the system. If the scan has spammed files all over the file system or in certain directories, cleaning up should be straight forward as the extension only creates files with the name `Ic4nh4z1t`.
