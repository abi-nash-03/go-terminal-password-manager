package main
import (
	"fmt"
	"log"
	"os"
	"path/filepath"
    "bufio"
    "strings"
    "strconv"
    "math"
    "crypto/rand"
    "bytes"
	"crypto/aes"
	"crypto/cipher"
    "encoding/base64"
    "flag"
    "github.com/atotto/clipboard"
)

func main() {
    initializePasswordFile()
    add_password := flag.Bool("add", false, "Add new password")
    delete_key := flag.String("d", "", "Delete a Key")
    flag.Parse()
    if(*add_password) {
        addNewPassword()
    } else if *delete_key != "" {
        deleteKey(*delete_key)
    } else {
        password_list := listPasswords()
        fmt.Printf("Enter the number : ")
        index := getUserInput()
        copyPasswordToCb(password_list, index)
    }
}

func addNewPassword() {
    fmt.Println("Enter the key to store")
    key := getUserInput()
    fmt.Println("Enter the password")
    password := getUserInput()
    fmt.Println(key, password)
    storePassword(key, password);
    fmt.Println("Password added successfully :)")
}

func deleteKey(key string) {
    // open the file
    file_path := getPasswordFilePath("password")
    password_file, err := os.OpenFile(file_path, os.O_RDONLY, 0600)
    if(err != nil) {
        fmt.Println("Unable to store the file")
        panic(err)
    }

    defer password_file.Close();

    // read line
    lines := [] string{}
    scanner := bufio.NewScanner(password_file)
    key_found := false
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if parts[0] == key {
            key_found = true
            continue
        } else {
            lines = append(lines, line)
        }
    }

    if !key_found {
        fmt.Println("Key not found!")
        return
    }
    writeIntoFile(file_path, lines)
}


func writeIntoFile(file_path string, string_arr []string) {
    // store the password
    password_file_w, w_err := os.OpenFile(file_path, os.O_CREATE | os.O_WRONLY | os.O_TRUNC, 0600)
    if(w_err != nil) {
        fmt.Println("Unable to store the file")
        panic(w_err)
    }
    defer password_file_w.Close();

    output := strings.Join(string_arr, "\n")
    writer := bufio.NewWriter(password_file_w)
    _,write_err := writer.WriteString(output)
    if write_err != nil {
        panic(write_err)
    }

    // Flush the buffer to actually write the data
    flush_err := writer.Flush()
    if flush_err != nil {
        panic(flush_err)
    }
}

func getPasswordFilePath(file_name string) string {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatal("Could not get home directory:", err)
    }
    file_path := filepath.Join(homeDir, ".password_manager")
    switch file_name {
    case "password":
        file_path = filepath.Join(file_path, ".user_passwords")
    case "encrypt":
        file_path = filepath.Join(file_path, ".encrypt")
    }
    return file_path
}

func initializePasswordFile() {
    passwordFolder := getPasswordFilePath("")

    if _, err := os.Stat(passwordFolder); os.IsNotExist(err) {
        fmt.Println("First run detected. Setting up password manager...")

        // create the folder
        err := os.Mkdir(passwordFolder, os.ModePerm)
        if(err != nil) {
            log.Fatal("Could not create password Folder:", err)
        }

        // create a file to store user passwords
        file, err := os.OpenFile(passwordFolder+"/.user_passwords", os.O_CREATE|os.O_WRONLY, 0600)
        if err != nil {
            log.Fatal("Could not create password file:", err)
        }
        defer file.Close()

        // create a file to store encryption key
        encrypt, err := os.OpenFile(passwordFolder+"/.encrypt", os.O_CREATE|os.O_WRONLY, 0600)
        if(err != nil) {
            log.Fatal("Could not able to create encrypt file")
        }
        defer encrypt.Close()

        // write the key and iv into the file
        key := "key:"+randomBase64String(32)
        iv := "iv:"+randomBase64String(16)
        whole_string := key+"\n"+iv
        _, err = encrypt.WriteString(whole_string)
        if err != nil {
            panic(err)
        }

        fmt.Println("Password file created at:", passwordFolder)
    } else {
        fmt.Println("Password manager already initialized.")
    }
}

func getUserInput() string {
	var input string
	_, err := fmt.Scanln(&input)

	if(err != nil){
		return input
	}
	return input
}

func storePassword(key, password string) {
    
    // open the file
    file_path := getPasswordFilePath("password")
    password_file, err := os.OpenFile(file_path, os.O_RDONLY, 0600)
    if(err != nil) {
        fmt.Println("Unable to store the file")
        panic(err)
    }

    defer password_file.Close();

    encrypted_password, enc_err := encryptText(password)
    if(enc_err != nil) {
        panic(enc_err)
    }

    // read line
    lines := [] string{}
    scanner := bufio.NewScanner(password_file)
    key_updated := false
    for scanner.Scan() {

        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if parts[0] == key {
            key := parts[0]
            value := encrypted_password
            new_line := key+":"+value
            lines = append(lines, new_line)
            key_updated = true
            break
        } else {
            lines = append(lines, line)
        }
    }
    if !key_updated {
        new_key_value_store := key+":"+encrypted_password
        lines = append(lines, new_key_value_store)
    }

    if scanner_err := scanner.Err(); err != nil {
        panic(scanner_err)
    } 

    // store the password
    writeIntoFile(file_path, lines)
}

func listPasswords() [] string {
    file_path := getPasswordFilePath("password")
    password_file, err := os.OpenFile(file_path, os.O_RDONLY, 0600)
    var passwords []string

    if err != nil {
		fmt.Println("Error opening password file:", err)
		panic(err)
	}
	defer password_file.Close()

    // Read line by line
	scanner := bufio.NewScanner(password_file)
    idx := 0    
    for scanner.Scan() {
        idx += 1

        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if len(parts) == 2 {
            key := parts[0]
            encrypted_password := parts[1]
            decrypted_password,err := decryptText(encrypted_password)
            if(err != nil) {
                panic(err)
            }
            passwords = append(passwords, decrypted_password)
            fmt.Printf("%d. %s \n", idx, key)
        }

    }

    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading file. \n")
    } 

    return passwords
}

func copyPasswordToCb(passwords [] string, index string) {

    // string to int
    int_index, err := strconv.Atoi(index)
    if err != nil {
        fmt.Println("Error while converting string to int")
        panic(err)
    }

    int_index -= 1
    if int_index >= len(passwords) {
        fmt.Println("index out of range")
        return
    }

    // copy password to clipboard
    password_to_copy := passwords[int_index]
    clipboard.WriteAll(password_to_copy)
}

func encryptText(plaintext string)  (string, error) {
    encrypt_keys := getPasswordEncryptKey()
    key := encrypt_keys[0]
    iv := encrypt_keys[1]

	var plainTextBlock []byte
	length := len(plaintext)
    if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}
    copy(plainTextBlock, plaintext)
	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

    cipher_text := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(cipher_text, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(cipher_text)

	return str, nil
}

func getPasswordEncryptKey() []string {
    file_path := getPasswordFilePath("encrypt")
    
    encrypt_file, err := os.OpenFile(file_path, os.O_RDONLY, 0600);
    if err != nil {
		panic(err)
	}
	defer encrypt_file.Close()

    var encrypt_keys []string
   
    // Read line by line
	scanner := bufio.NewScanner(encrypt_file)
    idx := 0    
    for scanner.Scan() {
        idx += 1

        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)

        if len(parts) == 2 {
            encrypt_keys = append(encrypt_keys, parts[1])
        }

    }
    return encrypt_keys
}

func decryptText(encrypted_text string) (string, error) {
    encrypt_keys := getPasswordEncryptKey()
    key := encrypt_keys[0]
    iv := encrypt_keys[1]
    ciphertext, err := base64.StdEncoding.DecodeString(encrypted_text)
    if err != nil {
		return "", err
	}

    block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

    if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("block size cant be zero")
	}

    mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext, err = PKCS5UnPadding(ciphertext)

	return string(ciphertext), nil
}

func randomBase64String(l int) string {
    buff := make([]byte, int(math.Ceil(float64(l)/float64(1.33333333333))))
    rand.Read(buff)
    str := base64.RawURLEncoding.EncodeToString(buff)
    return str[:l] // strip 1 extra character we get from odd length results
}

// PKCS5UnPadding function to remove padding
func PKCS5UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	paddingLen := int(data[length-1])
	if paddingLen > length {
		return nil, fmt.Errorf("invalid padding length")
	}
	return data[:length-paddingLen], nil
}