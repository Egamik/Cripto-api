CREATE TABLE certs (
	serialNumber INT PRIMARY KEY,
	subject VARCHAR NOT NULL,
	notBefore	DATE NOT NULL,
	notAfter	DATE NOT NULL,
	rawIssuer	BYTEA NOT NULL,
	isCA		BOOL NOT NULL
);
