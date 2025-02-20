The SSH Key is stored in Documents/ACCOUNTS/LVS directory. It is titled lvs-msr. 
The public key is lvs-msr.pub and has been added to the GitHub.
The private key has been added with the script ssh-keygen.sh

GIT COMMANDS:

#Get the List of Tags:
git ls-remote --tags origin

#get the Commit Has associated with a Tag:
git rev-list -n 1 <tag name> 


#Now get the commit hashes associated with all the files in that tag
git ls-tree -r <commit-hash-of-the-tag>

#Now get the file that has a particular Commit Hash
git checkout <commit-hash> -- <File Name>
git restore --source=<commit-hash> filename.txt