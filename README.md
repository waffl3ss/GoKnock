# GoKnock - v0.8 

#### Please make sure to actually utilize the README. 

Designed to validate potential usernames by querying OneDrive and/or Microsoft Teams, which are passive methods.  
It can also get details from Teams, such as availability, device type, and out of office message.
Finally, it also creates a nice clean list for future usage, all conducted from a single tool. 

If youre having problems with the token, you didnt go through the README, or you didnt use the interactive firefox option.


If building from source:
```
go mod init GoKnock
go mod tidy
go build
```

### v0.8 QoL and Fixes
- Teams enumeration was having some issues, that is now fixed. 
- OneDrive enumeration broke again, but now using a headless browser to get the tenant name, or you can provide the tenant name manually by going to https://tenantidlookup.com and getting the first value of the .onmicrosoft.com line
- Progress bar implemented and working.
- Removed the Legacy Skype option, as its no longer useful.
- General QoL improvements to ensure valid functionality.
- Im no longer providing the binaries... if you cant build it, dont use it.

### v0.5 Tenant Lookup Fixes
- Implemented a new way to find the tenant name. Should be much better at actually getting the tenant name now.

### v0.3 Initial Release
- Initial release of the go version of KnockKnock.

### Latest 
- Microsoft changed things (as always) and had to figure out a new method of getting the TenantID to use in the OneDrive Enum stuffs.
- If you cant get the token normally, you can use `-t proxy` to have a selenium firefox browser open on your system, where you login to your MS account, and it grabs the token for you before exiting and continuing the enumeration. 
- Teams has changed the what the teams token can access. It can still enumerate teams for now, but cant do the teams status. Therefore, at the end of the README, ive included a way to manually get a better token that can do both. That being said, the interactive proxy mode (`-t proxy`) gets the better token right away.

------------------------------------------------------------------------------------
# Options
- You can select one or both modes, as long as the appropriate options are provided for the modules selected.
- When running both OneDrive and Teams enumeration, it will remove verified users from the first function as to not check them again in the second function. 
- Both modules will require the domain flag (-d) and the user input list (-i).  
- The tool does not require an output file as an option, and if not supplied, it will print to screen only.  
- Verbose mode outputs a lot of data, but even more so when using the proxy. You have been warned.
- The Teams option requires a bearer token. The script automatically parses the token to get whats needed for authentication. (highly recommend the `-t proxy` option to get the token)  
- The STATUS (-s) option shows user teams availability, device, and OutOfOffice message, then writes it to a seperate file (Output option (-o) required). (Old teams token dosnt work for this. Documentation on getting the new token is at the bottom of the README)

------------------------------------------------------------------------------------

# Usage

```
    .d8888b.           888    d8P                             888      
   d88P  Y88b          888   d8P                              888      
   888    888          888  d8P                               888      
   888         .d88b.  888d88K     88888b.   .d88b.   .d8888b 888  888 
   888  88888 d88""88b 8888888b    888 "88b d88""88b d88P"    888 .88P 
   888    888 888  888 888  Y88b   888  888 888  888 888      888888K  
   Y88b  d88P Y88..88P 888   Y88b  888  888 Y88..88P Y88b.    888 "88b 
    "Y8888P88  "Y88P"  888    Y88b 888  888  "Y88P"   "Y8888P 888  888 
      
          v0.8                                              @waffl3ss

  -d string
        Domain to target (required)
  -i string
        Input file with newline-separated users to check (required)
  -o string
        Write output to file
  -onedrive
        Run the One Drive Enumeration Module
  -s    Write Teams Status for users to a separate file
  -t string
        Teams Token, either file, string, or 'proxy' for interactive Firefox
  -teams
        Run the Teams User Enumeration Module
  -tenant string
    	Manually specify tenant name for OneDrive enumeration (e.g., 'contoso' for contoso.onmicrosoft.com)
  -threads int
        Number of threads to use in the Teams User Enumeration (default 10)
  -v    Show verbose errors
```
### Examples

```
./goknock -teams -i UsersList.txt -d Example.com -o OutFile.txt -t BearerToken.txt
./goknock -teams -i UserList.txt -d Example.com -o OutFile.txt -t proxy
./goknock -onedrive -i UsersList.txt -d Example.com -o OutFile.txt
./goknock -onedrive -teams -i UsersList.txt -d Example.com -t BearerToken.txt 
./goknock -onedrive -teams -i UsersList.txt -d Example.com -t BearerToken.txt -tenant contoso

```

------------------------------------------------------------------------------------

# Getting Your Token
The teams token has changed. You can still get the token by using a web browser, logging into teams, opening the dev tools, and getting the authtoken cookie. With that said, the authtoken cookie no longer has access to additional information outside of the general enumeration. So youll know why youre not getting status if you use that token.

There is another token that can be used, but requires more interaction. I have modified the interactive firefox (`-t proxy`) to get the correct token, so use that if you cant figure out the rest. 

For an example of how to get the other special token, you need to proxy through burp. Setup burp and a fresh browser, go to `https://teams.microsoft.com` and login. Once the loading is complete, youre going to look for a POST request to `https://login.microsoftonline.com` and the endpoint will be something like this `/123a4b56-789c-12def3h4i567/oauth2/v2.0/token?client-request-id=Core-z9y8765x-432w-10v9-ut87-6s543r2109q8` and within the response json youll see a value for "access_token". Thats the value you want to use for the token. 

Note: There will be a few POST to endpoints with `/oauth2/v2.0/token?` in it. Make sure to find the one that I mention above, obviously the random values are fake in this and will be completly different in your request. Again, the interactive proxy takes care of all this for you...

# References

[TenantIDLookup](https://tenantidlookup.com/)  
[@nyxgeek](https://github.com/nyxgeek) - [onedrive_user_enum](https://github.com/nyxgeek/onedrive_user_enum)  
[@immunIT](https://github.com/immunIT) - [TeamsUserEnum](https://github.com/immunIT/TeamsUserEnum)  

