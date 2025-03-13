curl -X POST -H "Content-Type: application/json" -d '{"name":"John","surname":"Doe","password":"johndoe123", "is_admin":"0"}' localhost:8080/api/user/fix-id
curl -X POST -H "Content-Type: application/json" -d '{"name":"Jane","surname":"Smith","password":"janesmith123", "is_admin":"1"}' localhost:8080/api/user/fix-id
curl -X POST -H "Content-Type: application/json" -d '{"name":"Alice","surname":"Johnson","password":"alicejohnson123", "is_admin":"0"}' localhost:8080/api/user/fix-id
curl -X POST -H "Content-Type: application/json" -d '{"name":"Bob","surname":"Brown","password":"bobbrown123", "is_admin":"0"}' localhost:8080/api/user/fix-id
curl -X POST -H "Content-Type: application/json" -d '{"name":"Charlie","surname":"Davis","password":"charliedavis123", "is_admin":"0"}' localhost:8080/api/user/fix-id

curl -X POST -H "Content-Type: application/json" -d '{"name":"RipCurl","adress":"1 Unicorn drive"}' localhost:8080/api/supplier
curl -X POST -H "Content-Type: application/json" -d '{"name":"Unicorn","adress":"1 Boston Av"}' localhost:8080/api/supplier
curl -X POST -H "Content-Type: application/json" -d '{"name":"Zara","adress":"1 New York St"}' localhost:8080/api/supplier