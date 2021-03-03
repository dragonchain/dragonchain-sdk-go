package dragonchain

type Status struct {
	Id							string		`json:id`
	Level						int8			`json:level`
	Url							string		`json:url`
	HashAlgo				string		`json:hashAlgo`
	Scheme					string		`json:scheme`
	Version					string		`json:version`
	EncryptionAlgo	string		`json:encryptionAlgo`
	IndexingEnabled	bool			`json:indexingEnabled`
}

type ErrorDetails struct {
	Type		string		`json:type`
	Details	string		`json:details`
}