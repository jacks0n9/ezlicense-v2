# EzLicense
```
   __         __   _                               
  /__\ ____  / /  (_)  ___   ___  _ __   ___   ___ 
 /_\  |_  / / /   | | / __| / _ \| '_ \ / __| / _ \
//__   / / / /___ | || (__ |  __/| | | |\__ \|  __/
\__/  /___|\____/ |_| \___| \___||_| |_||___/ \___|
                                                   
```
## A simple code license package for go. Generate and validate licenses with expiration dates, with no server infrastructure
EzLicense is a package to allow you do generate licenses for your software, which can contain an expiration date and trusted additional data, proving that a user owns the software.

For time-based license verification, EzLicense can take advantage of the "Date" header returned by http requests to most websites. This means that you don't need to have any server infrastructure to host a trusted time source for license expiration date verification.
# Usage of EzLicense
## Parts
There are two main parts in the ezlicense project, the license generator and the license validator.
## License Generator
### Before you generate a new license, you must generate an admin license program first, which contains your private key as well as information for the license header. As a design decision, you must write your own code to generate the license.
```go
package main

import (
    ez "github.com/jacks0n9/ezlicense-v2"
)
func main(){
    program,err:=ez.NewAdminLicenseProgram("EXAMPLE LICENSE NAME",2048)
    // Make sure to save this for later
    key:=ez.ExportPrivateKey(program.PrivateKey)
}
```
### To generate a license with the program:
```go
import "time"
license,err:=program.GenerateLicense(ez.LicenseData{
    // Make license expire one day from now
    Expires: time.Now().Unix() + (int64(time.Hour.Seconds()) * 24),
    // You can set any arbitrary data
    AdditionalData: map[string]interface{}{
        "email":"example.com"
        "adjfeweefw":3
    }
})
```
### Your license can then be distributed

## License Validator
### You first must load a client license program

```go

const EXAMPLE_PUB_KEY=`
-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA7+Ry/9TA8R9VHMHkm8AXW6n3EzKkl+E1iFUSHPDJiIQCRsPAV6U2
ygeUOlOgSJaPFQ00NtcSuh0RwLj3e6DWFR85WkmxGwwVl9wDD1Q4ppuhMurvR3bF
L0wglZSu+GCywpIFWX1/1Abi9bVjjs36VpF0cHg8uFbYp0G5ODFnUzOV4NqAWTZZ
krKDpcB8/IaUXWhsTDs448UJqfC1X0lsOySdyOLjv5lb0tB1ng4GD8zxEpXjZNu7
F8taK8GKS/HUkgSEj6XIQ2ITdmAerL6aWgMGB61xJhE7ui9XphhcjKtgeIaxmyCi
VelZYSXtspd9CTGzWiSCD/b+AP/pCupqPQIDAQAB
-----END PUBLIC KEY-----`

func main(){
    // Use our utility functions to easily read a pem key
    loaded,err:=ez.ReadPemPublicKey(EXAMPLE_PUB_KEY)
    // A time verifier is responsible for checking if the expiration date is correct
    prog:=client.NewClientLicenseProgram(&loaded,ez.NewDefaultTimeVerifier())
}
```

### To verify a license
```go
const EXAMPLE_LICENSE=`
-----BEGIN LICENSE FOR EXAMPLE-----
eyJkYXRhIjoiZXlKbGVIQnBjbVZ6SWpveE5qa3lNekV5TWpNeUxDSmhaR1JwZEds
dmJtRnNYMlJoZEdFaU9uc2lTR1ZzYkc4aU9pSlhiM0pzWkNKOWZRPT0iLCJzaWdu
YXR1cmUiOiJneUk2Y0QxYXNUcWtXT2ZVLzFZNFYrS2gzemRLZlpBNmlEUFF0SHBQ
Y2FNKzZsVXo3WVFudGFpVHhGckpEQlRBSS8vSnh3bVRKdExCUm9sRFNuZmdJb25B
VG5iYUhSRHdoZVF1QVpQeC8vYlNOZjBwN1UzUVN4cExsNTlRQjhRdCs4QVUxa2ls
TEhTbit5T3F6aGQxRFBGQ2xia3JDT3FOSk01THEzS2ZmcTRJZ2IveUhsRDVXVnli
Z2d1M2FuYUZNNlowbXU3bTdLOUFSUWRPOW5sMEdYcEtVcWtjMmJKZnVJam5RSDl3
TThlYldzY1ZhT3pOcE9sbVp1bWdrN09Fa0ltVWI1UXNOWC9iN3Z0NjF0MkdlQ2NZ
SHZFUnFIb1hHQUQ3Y3RVWlBzeXRxRmdzaGhxYTc4NFJDa2pSeXIrYnZROXFRUjU0
SmZBSlpZaFFyZHVOQkE9PSJ9
-----END LICENSE FOR EXAMPLE-----`

// Will return an error if the license is invalid
// Also will give you the additional data that you added earlier
data,err:=prog.VerifyLicense(EXAMPLE_LICENSE)
```
### Continuous license expriation verification checks, in a goroutine while your app is running, if the license is expired, instead of just checking when verifylicense is called
```go
program.ExpirationCheckInterval=time.Second*30
program.OnExpire=func(data ez.LicenseData){
    fmt.Println("Your license is expired")
}
```
That's all you need to easily protect your app!

 Keep in mind that with some intermediate code reverse-engineering skills, someone skill could use your app without a license e.g. by removing the code that checks your license or replacing the public key with their own.