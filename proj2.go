package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username   string
	Passphrase []byte
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	Uuid       uuid.UUID

	MyFileTable     map[string]uuid.UUID
	SharedFileTable map[string][]byte //filename -> bytes that generate the uuid of rerouter
	MyFileKeyTable  map[string][]byte
	ShareTable      map[string]map[string]uuid.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// type Pair struct {
// 	Filename string
// 	Username string
// }

type FileHead struct {
	SegmentTable  map[int]uuid.UUID
	KeyTable      map[int][]byte
	NumOfSegments int
}

func CheckIntegrity(passphrase []byte, uid uuid.UUID) error {
	hmacKey, err1 := userlib.HMACEval(passphrase, []byte("keyforhmac"))
	if err1 != nil {
		return errors.New("Can't generate HMAC key")
	}
	hmacKey = hmacKey[:16]
	cipher, exists := userlib.DatastoreGet(uid)
	if !exists {
		return errors.New("UUID not in Datastore or UUID tampered")
	}
	lentext := len(cipher)
	MAC := cipher[(lentext - 64):]
	encryptedData := cipher[:(lentext - 64)]
	testMac, err := userlib.HMACEval(hmacKey, encryptedData)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(MAC, testMac) {
		return errors.New("DataStore was tampered.")
	}
	return nil
}

// type File struct {
// 	Passphrase []byte
// 	content    []byte
// 	nextUuid   uuid.UUID
// }

//Secure upload function that stores in the Datastore at uuid after encryption and HMAC
func SecureUpload(passphrase []byte, data []byte, uid uuid.UUID) error {
	var err1 error
	encryptKey, err1 := userlib.HMACEval(passphrase, []byte("keyforencryption"))
	if err1 != nil {
		return errors.New("Can't generate encryption key")
	}
	encryptKey = encryptKey[:16]
	hmacKey, err1 := userlib.HMACEval(passphrase, []byte("keyforhmac"))
	if err1 != nil {
		return errors.New("Can't generate HMAC key")
	}
	hmacKey = hmacKey[:16]
	cipherText := userlib.SymEnc(encryptKey, userlib.RandomBytes(16), data)
	mac, err1 := userlib.HMACEval(hmacKey, cipherText)
	if err1 != nil {
		return errors.New("Error")
	}
	userlib.DatastoreSet(uid, append(cipherText, mac...))
	return err1
}

//Secure Fetch function that download data from Datastore
func SecureFetch(passphrase []byte, uid uuid.UUID) (data []byte, err error) {
	cipher, exists := userlib.DatastoreGet(uid)
	if !exists {
		return nil, errors.New("UUID not in Datastore.")
	}
	err = CheckIntegrity(passphrase, uid)
	if err != nil {
		return nil, err
	}
	encryptKey, err := userlib.HMACEval(passphrase, []byte("keyforencryption"))
	if err != nil {
		return nil, errors.New("Error")
	}
	encryptKey = encryptKey[:16]
	// hmacKey, err := userlib.HMACEval(passphrase, []byte("macAndCheese"))
	// if err != nil {
	// 	return nil, errors.New("Error")
	// }
	// hmacKey = hmacKey[:16]
	lentext := len(cipher)
	encryptedData := cipher[:(lentext - 64)]
	//MAC := cipher[(lentext - 64):]
	// testMac, err := userlib.HMACEval(hmacKey, encryptedData)
	// if !userlib.HMACEqual(MAC, testMac) {
	// 	return nil, errors.New("Datastore was tampered.")
	// }
	data = userlib.SymDec(encryptKey, encryptedData)
	return data, nil
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	userdataptr.Username = username
	nameBytes := []byte(username)
	passBytes := []byte(password)
	var passphrase []byte

	//passphrase generated by password and username:
	passphrase = userlib.Argon2Key(passBytes, nameBytes, 32)
	userdataptr.Passphrase = passphrase

	//asymmetric public key and private key:
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	var err1 error
	pk, sk, err1 = userlib.PKEKeyGen()
	if err1 != nil {
		return nil, errors.New("Error while generating aymmetric key pair!")
	}
	userdataptr.PrivateKey = sk

	//signature public and private key:
	var sign userlib.DSSignKey
	var verify userlib.DSVerifyKey
	sign, verify, err1 = userlib.DSKeyGen()
	if err1 != nil {
		return nil, errors.New("Error while generating signature key pair!")
	}
	userdataptr.SignKey = sign

	// store public keys
	err1 = userlib.KeystoreSet(username+"/asym", pk)
	if err1 != nil {
		return nil, errors.New("Error while storing public key")
	}
	err1 = userlib.KeystoreSet(username+"/sign", verify)
	if err1 != nil {
		return nil, errors.New("Error while storing verification key")
	}

	//uuid = uuid(hmac(passphrase, username))
	var uid uuid.UUID
	hmac, _ := userlib.HMACEval(passphrase, []byte(username))
	uid, _ = uuid.FromBytes(hmac[:16])

	//file tables and share list
	userdata.Uuid = uid
	userdata.MyFileTable = make(map[string]uuid.UUID)
	userdata.SharedFileTable = make(map[string][]byte)
	userdata.MyFileKeyTable = make(map[string][]byte)
	userdata.ShareTable = make(map[string]map[string]uuid.UUID)

	//marshall and store user's info
	marshalled, _ := json.Marshal(userdata)
	err1 = SecureUpload(passphrase, marshalled, uid)
	if err1 != nil {
		return nil, err1
	}

	return &userdata, err1
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//generate passphrase
	passBytes := []byte(password)
	nameBytes := []byte(username)
	passphrase := userlib.Argon2Key(passBytes, nameBytes, 32)

	//get uuid:
	//uuid = uuid(hmac(passphrase, username))
	var uid uuid.UUID
	hmac, _ := userlib.HMACEval(passphrase, []byte(username))
	uid, _ = uuid.FromBytes(hmac[:16])

	//fetch data
	userData, err := SecureFetch(passphrase, uid)
	if err != nil {
		return nil, err
	}

	//unmarshall

	err = json.Unmarshal(userData, userdataptr)
	if err != nil {
		return nil, err
	}

	//TODO Do we need double check user's password here?

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	err := CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return
	}
	// initialize a filhead
	var filehead FileHead
	fileptr := &filehead
	filehead.NumOfSegments = 1
	filehead.SegmentTable = make(map[int]uuid.UUID)
	filehead.KeyTable = make(map[int][]byte)

	FileHeadUUID := uuid.New()
	FileHeadMasterKey := userlib.RandomBytes(16) // This key will actually be used to create FileHeadEncryptKey and FileHeadSignatureShareEncryptKey
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(FileHeadMasterKey, []byte("GetFileHeadEncryptKey"))
	FileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]

	// Create the new #1 segment to hold contents, and upload it
	FileSegmentUUID := uuid.New()
	FileSegmentKey := userlib.RandomBytes(16)

	//TODO handle error
	SecureUpload(FileSegmentKey, data, FileSegmentUUID)

	// Initialize maps in filehead, and put segment #1 into them at mapping for 0
	fileptr.SegmentTable[0] = FileSegmentUUID
	fileptr.KeyTable[0] = FileSegmentKey

	// Upload filehead
	marshalledFileHead, _ := json.Marshal(filehead)
	SecureUpload(FileHeadEncryptKey, marshalledFileHead, FileHeadUUID)

	// Add filehead to user's file tables
	userdata.MyFileTable[filename] = FileHeadUUID
	userdata.MyFileKeyTable[filename] = FileHeadMasterKey

	// Upload updated user struct
	marshalledUser, _ := json.Marshal(userdata)
	SecureUpload(userdata.Passphrase, marshalledUser, userdata.Uuid)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	err = CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return err
	}
	var sharing bool
	var bytesRerouterUid []byte
	uid, exists := userdata.MyFileTable[filename]
	if !exists {
		bytesRerouterUid, sharing = userdata.SharedFileTable[filename]
		if !sharing {
			return errors.New("File not found")
		}
	}
	passphrase := userdata.MyFileKeyTable[filename]
	if err != nil {
		return err
	}

	if sharing {
		rerouterKey, err1 := userlib.HMACEval(passphrase, []byte("keyOfRerouter"))
		if err1 != nil {
			return err1
		}
		rerouterKey = rerouterKey[:16]
		rerouter, err1 := SecureFetch(rerouterKey, bytesToUUID(bytesRerouterUid))
		if err1 != nil {
			return err1
		}
		err1 = json.Unmarshal(rerouter, &uid)
		if err1 != nil {
			return err1
		}
	}
	FileHeadEncryptKeyOverflow, _ := userlib.HMACEval(passphrase, []byte("GetFileHeadEncryptKey"))
	FileHeadEncryptKey := FileHeadEncryptKeyOverflow[:16]
	marshalledFilehead, err := SecureFetch(FileHeadEncryptKey, uid)

	var fileHead FileHead
	err = json.Unmarshal(marshalledFilehead, &fileHead)
	if err != nil {
		return err
	}
	newSegUid := uuid.New()
	newSegKey := userlib.RandomBytes(16)
	SecureUpload(newSegKey, data, newSegUid)

	segNum := fileHead.NumOfSegments
	fileHead.SegmentTable[segNum] = newSegUid
	fileHead.KeyTable[segNum] = newSegKey
	fileHead.NumOfSegments = segNum + 1
	marshalledFileHead, _ := json.Marshal(fileHead)
	err = SecureUpload(FileHeadEncryptKey, marshalledFileHead, uid)
	return err
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	err = CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return nil, err
	}
	var uid uuid.UUID
	var exists bool
	var sharing bool
	var bytesRerouterUid []byte
	uid, exists = userdata.MyFileTable[filename]
	if !exists {
		bytesRerouterUid, sharing = userdata.SharedFileTable[filename]
		if !sharing {
			return nil, errors.New("No file")
		}
	}
	passphrase := userdata.MyFileKeyTable[filename]
	FileHeadEncryptKey, _ := userlib.HMACEval(passphrase, []byte("GetFileHeadEncryptKey"))
	FileHeadEncryptKey = FileHeadEncryptKey[:16]

	if sharing {
		rerouterKey, err1 := userlib.HMACEval(passphrase, []byte("keyOfRerouter"))
		if err1 != nil {
			return nil, err1
		}
		rerouterKey = rerouterKey[:16]
		rerouter, err1 := SecureFetch(rerouterKey, bytesToUUID(bytesRerouterUid))
		if err1 != nil {
			return nil, err1
		}
		err1 = json.Unmarshal(rerouter, &uid)
		if err1 != nil {
			return nil, err1
		}
	}

	marshalledFilehead, err := SecureFetch(FileHeadEncryptKey, uid)
	if err != nil {
		return nil, err
	}

	var fileHead FileHead
	err = json.Unmarshal(marshalledFilehead, &fileHead)
	if err != nil {
		return nil, err
	}
	var segment []byte
	var segmentUID uuid.UUID
	var segmentKey []byte
	for i := 0; i < fileHead.NumOfSegments; i++ {
		segmentUID = fileHead.SegmentTable[i]
		segmentKey = fileHead.KeyTable[i]
		// No need to unmarshal, file data is never marshalled in the first place
		segment, err = SecureFetch(segmentKey, segmentUID)
		if err != nil {
			return nil, err
		}
		data = append(data, segment...)
	}

	return data, err
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	err = CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return "", err
	}
	var sharing bool
	var bytesRerouterUid []byte
	uid, exists := userdata.MyFileTable[filename]
	if !exists {
		bytesRerouterUid, sharing = userdata.SharedFileTable[filename]
		if !sharing {
			return "", errors.New("No file")
		}
	}
	//Grab recipient's public key
	publicKey, beThere := userlib.KeystoreGet(recipient + "/asym")
	if !beThere {
		return "", errors.New("Can't find the recipient.")
	}

	fileHeadKey := userdata.MyFileKeyTable[filename]
	rerouterKey, _ := userlib.HMACEval(fileHeadKey, []byte("keyOfRerouter"))
	rerouterKey = rerouterKey[:16]
	var rerouterUid uuid.UUID
	if !sharing {
		bytesRerouterUid = userlib.RandomBytes(16)
		//create the rerouter
		rerouterUid = bytesToUUID(bytesRerouterUid)
		bytesUid, _ := json.Marshal(uid)
		SecureUpload(rerouterKey, bytesUid, rerouterUid)
	} else {
		rerouterUid = bytesToUUID(bytesRerouterUid)
		_, err = SecureFetch(rerouterKey, rerouterUid)
		if err != nil {
			return "", err
		}
	}

	//create the message:
	//bytesRerouterUid, _ := json.Marshal(uid)
	bytesSignatureUid := userlib.RandomBytes(16)
	signatureUid := bytesToUUID(bytesSignatureUid)
	//marshalledSignatureUid, _ := json.Marshal(signatureUid)
	message := append(bytesRerouterUid, fileHeadKey...)
	message = append(message, bytesSignatureUid...)
	encryptedMessage, err1 := userlib.PKEEnc(publicKey, message)
	if err1 != nil {
		return "", err1
	}

	//sign and secureUpload the signature in DataStore
	signedMessage, err1 := userlib.DSSign(userdata.SignKey, encryptedMessage)
	if err1 != nil {
		return "", err1
	}
	signatureKey, err1 := userlib.HMACEval(fileHeadKey, []byte("keyOfSignature"))
	if err1 != nil {
		return "", err1
	}
	signatureKey = signatureKey[:16]
	SecureUpload(signatureKey, signedMessage, signatureUid)

	//update sender's user info and secure upload
	if userdata.ShareTable[filename] == nil {
		userdata.ShareTable[filename] = make(map[string]uuid.UUID)
	}
	userdata.ShareTable[filename][recipient] = rerouterUid
	marshalledUser, _ := json.Marshal(userdata)
	SecureUpload(userdata.Passphrase, marshalledUser, userdata.Uuid)
	return string(encryptedMessage), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	err := CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return err
	}
	encryptedMessage := []byte(magic_string)

	//test sender exists
	veridfyKey, exists := userlib.KeystoreGet(sender + "/sign")
	if !exists {
		return errors.New("Sender's verification key not found!")
	}

	//decrypt message and grab signature uid
	message, err := userlib.PKEDec(userdata.PrivateKey, encryptedMessage)
	if err != nil {
		return err
	}
	signatureUid := bytesToUUID(message[32:])
	if err != nil {
		return err
	}
	fileHeadKey := message[16:32]

	//verify the signature
	signatureKey, err1 := userlib.HMACEval(fileHeadKey, []byte("keyOfSignature"))
	if err1 != nil {
		return err1
	}
	signatureKey = signatureKey[:16]
	signature, err1 := SecureFetch(signatureKey, signatureUid)
	if err1 != nil {
		return err1
	}
	err = userlib.DSVerify(veridfyKey, encryptedMessage, signature)
	if err != nil {
		return errors.New("Unable to verify signature on magic string")
	}

	//Grab rerouter uuid and go to the file had
	rerouterUidBytes := message[:16]
	rerouterUid := bytesToUUID(rerouterUidBytes)
	rerouterKey, err4 := userlib.HMACEval(fileHeadKey, []byte("keyOfRerouter"))
	rerouterKey = rerouterKey[:16]
	if err4 != nil {
		return err4
	}
	rerouter, err5 := SecureFetch(rerouterKey, rerouterUid)
	if err5 != nil {
		return err5
	}
	var fileHeadUid uuid.UUID
	err = json.Unmarshal(rerouter, &fileHeadUid)
	if err != nil {
		return err
	}

	fileHeadEncryptKey, _ := userlib.HMACEval(fileHeadKey, []byte("GetFileHeadEncryptKey"))
	fileHeadEncryptKey = fileHeadEncryptKey[:16]
	_, err6 := SecureFetch(fileHeadEncryptKey, fileHeadUid)
	if err6 != nil {
		return err6
	}
	userdata.SharedFileTable[filename] = rerouterUidBytes
	userdata.MyFileKeyTable[filename] = fileHeadKey
	marshalledUser, _ := json.Marshal(userdata)
	SecureUpload(userdata.Passphrase, marshalledUser, userdata.Uuid)
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	var rerouterUid uuid.UUID
	err = CheckIntegrity(userdata.Passphrase, userdata.Uuid)
	if err != nil {
		return err
	}
	_, exists := userdata.MyFileTable[filename]
	if !exists {
		return errors.New("You do not own this file")
	}

	//TODO maybe no error in this case
	rerouterUid, exists = userdata.ShareTable[filename][target_username]
	if !exists {
		return errors.New("No need to revoke")
	}

	userlib.DatastoreDelete(rerouterUid)
	delete(userdata.ShareTable[filename], target_username)
	marshalledUser, _ := json.Marshal(userdata)
	SecureUpload(userdata.Passphrase, marshalledUser, userdata.Uuid)
	return nil
}
