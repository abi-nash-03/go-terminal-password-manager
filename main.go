package main
import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	initializePasswordFile()
    var key, password string
	fmt.Println("Enter the key to store")
    key = getUserInput()
	fmt.Println("Enter the password")
	password = getUserInput()
	fmt.Println(key, password)
}

func getPasswordFilePath() string {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatal("Could not get home directory:", err)
    }
    return filepath.Join(homeDir, ".user_password")

}

func initializePasswordFile() {
    passwordFile := getPasswordFilePath()

    if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
        fmt.Println("First run detected. Setting up password manager...")

        file, err := os.OpenFile(passwordFile, os.O_CREATE|os.O_WRONLY, 0600)
        if err != nil {
            log.Fatal("Could not create password file:", err)
        }
        defer file.Close()

        fmt.Println("Password file created at:", passwordFile)
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