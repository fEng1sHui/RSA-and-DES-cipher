<!doctype html>
<html lang="pl">
<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <!-- <link rel="stylesheet" type="text/css" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css"> -->
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="stylesheet.css">

    <title>Bezpieczeństwo w systemach i sieciach komputerowych</title>
</head>
<body>
<br><br><br><br><br><br>
<h1 class="text-center"> Bezpieczeństwo w systemach i sieciach komputerowych </h1>
<h2 class="text-center"> Yurii Boiko gr K11</h2><br><br>
<form method="POST" action="encryption.php">
    <div class="containerForm">
        <div class="input-group">
            <input name="data" type="text" class="form-control" placeholder="Wpisz tekst do szyfrowania" aria-label="Szyfr" aria-describedby="basic-addon2" required>
            <div class="input-group-append">
                <button type="submit" name="rsa" class="btn btn-outline-secondary" type="button">RSA</button>
                <button type="submit" name="des" class="btn btn-outline-secondary" type="button">DES</button>
            </div>
        </div>
    </div>
</form><br/>

    <?php
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);

    /* RSA DATA */


    /*DES DATA*/

    // if you want use this on query string or in html page, you can encode this text in base64
    //$crypt = base64_encode($crypt);
    // first of decrypt you decode
    // $crypt = base64_decode($crypt);
    // decrypting text

    function cryptECB($crypt, $key) {
        $iv_size = mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        // crypting
        $cryptText = mcrypt_encrypt(MCRYPT_3DES, $key, $crypt, MCRYPT_MODE_ECB, $iv);

        return $cryptText;
    }
    function decryptECB($encrypted, $key) {
        $iv_size = mcrypt_get_iv_size(MCRYPT_3DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
        // decrypting
        $stringText = mcrypt_decrypt(MCRYPT_3DES, $key, $encrypted, MCRYPT_MODE_ECB, $iv);

        return $stringText;
    }

    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $data = $_POST['data'];
        if (isset($_POST['rsa'])) {
            echo '<p class="text-center"><b>Szyfrowanie RSA</b></p>';
            $start = microtime(true);
            // read the public key
            $public_key = openssl_pkey_get_public(file_get_contents('public_key.pem'));
            $public_key_details = openssl_pkey_get_details($public_key);
            // there are 11 bytes overhead for PKCS1 padding
            $encrypt_chunk_size = ceil($public_key_details['bits'] / 8) - 11;
            $output = '';
            // loop through the long plain text, and divide by chunks
            while ($data) {
                $chunk = substr($data, 0, $encrypt_chunk_size);
                $data = substr($data, $encrypt_chunk_size);
                $encrypted = '';
                if (!openssl_public_encrypt($chunk, $encrypted, $public_key))
                    die('Failed to encrypt data');
                $output .= $encrypted;
            }
            openssl_free_key($public_key);
            echo '<div class="containerSzyfr">
                      <div class="row">
                        <div class="col-2 border text-right"><b>Szyfrowany tekst: </b></div>
                        <div class="col border">'.base64_encode($output).'</div>
                      </div>
                      <div class="row">
                        <div class="col-2 border text-right"><b>Czas szyfrowania: </b></div>
                        <div class="col border">'.$time_elapsed_secs = microtime(true) - $start.'</div>
                      </div>';
            $start = microtime(false);
            $start = microtime(true);

            $cipher_text = base64_encode($output);
            // decode the text to bytes
            $encrypted = base64_decode($cipher_text);
            // read the private key
            $private_key = openssl_pkey_get_private(file_get_contents('private_key.pem'));
            $private_key_details = openssl_pkey_get_details($private_key);
            // there is no need to minus the overhead
            $decrypt_chunk_size = ceil($private_key_details['bits'] / 8);
            $output = '';
            // decrypt it back chunk-by-chunk
            while ($encrypted) {
                $chunk = substr($encrypted, 0, $decrypt_chunk_size);
                $encrypted = substr($encrypted, $decrypt_chunk_size);
                $decrypted = '';
                if (!openssl_private_decrypt($chunk, $decrypted, $private_key))
                    die('Failed to decrypt data');
                $output .= $decrypted;
            }
            openssl_free_key($private_key);
            echo '<div class="row">
                        <div class="col-2 border text-right"><b>Rozszyfrowany tekst: </b></div>
                        <div class="col border">'.$output.'</div>
                   </div>
                   <div class="row">
                        <div class="col-2 border text-right"><b>Czas rozszyfrowania: </b></div>
                        <div class="col border">'.$time_elapsed_secs = microtime(true) - $start.'</div>
                    </div>
                 </div>';
        }
        if (isset($_POST['des'])) {
            echo '<p class="text-center"><b>Szyfrowanie DES</b></p>';
            $key = "MYKEYFORCRYPTINGTEXT3421";
            $text = $data;

            $start = microtime(true);
            // crypting text
            $crypt = cryptECB($text, $key);
            echo '<div class="containerSzyfr">
                      <div class="row">
                        <div class="col-2 border text-right"><b>Szyfrowany tekst: </b></div>
                        <div class="col border">'.base64_encode($crypt).'</div>
                      </div>
                      <div class="row">
                        <div class="col-2 border text-right"><b>Czas szyfrowania: </b></div>
                        <div class="col border">'.$time_elapsed_secs = microtime(true) - $start.'</div>
                      </div>';
            $start = microtime(false);
            $start = microtime(true);

            $decrypt = decryptECB($crypt, $key);
            echo '<div class="row">
                        <div class="col-2 border text-right"><b>Rozszyfrowany tekst: </b></div>
                        <div class="col border">'.$decrypt.'</div>
                   </div>
                   <div class="row">
                        <div class="col-2 border text-right"><b>Czas rozszyfrowania: </b></div>
                        <div class="col border">'.$time_elapsed_secs = microtime(true) - $start.'</div>
                    </div>
                 </div>';
            $start = microtime(false);
        }
    }
    ?>
<!-- Optional JavaScript -->
<!-- jQuery first, then Popper.js, then Bootstrap JS -->
<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.1.1/js/bootstrap.min.js"></script>
</body>
</html>