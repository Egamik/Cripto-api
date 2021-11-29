package postdbconfig

import (
	"fmt"
)

const PostgresDriver = "postgres"

const User = "postgres"

const Host = "localhost"

const Port = "5432"

const Password = "seclab"

const DbName = "certificados"

const TableName = "certs"

var DataSourceName = fmt.Sprintf("host=%s port=%s user=%s "+"password=%s dbname=%s sslmode=disable", Host, Port, User, Password, DbName)
