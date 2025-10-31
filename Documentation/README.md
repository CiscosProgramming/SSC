# SSC
Francisco Rodrigues dos Santos 72908
Teresa Domingos 73433

Inicialmente o cliente pode escolher entre as seguintes variações de encriptação, que devem estar escritas da seguinte maneira no ficheiro cryptoconfig.txt:
    
    1º
    AES GCM
    KEYSIZE 256 bits
    2º 
    AES CBC PKCS5Padding
    KEYSIZE 256 bits
    HMAC-SHA256
    MACKEYSIZE: 256 bits
    3º
    CHACHA20 Poly1305
    KEYSIZE 256 bits
Para alterar o tipo de encriptação não é necessária a recompilação, apenas que o ficheiro seja salvo com as novas alterações.

Relativamente ao funcionamento deste projeto existem as seguintes particularidades. 
Em primeiro deve ser iniciado o ficheiro BlockStorageServer.java de modo a que posteriormente ao se inicializar BlockStorageClient que se consiga conectar ao Servidor.

    1º java BlockStorageServer
    2º java BlockStorageClient

O cliente como forma de identificação deve providenciar um id e uma palavra passe que funcionaram como "autenticação" e distinção de clientes. Estes campos vao ser pedidos do lado do Cliente através do terminal. 

    3º 1904 (exemplo)
    4º palavra passe (exemplo)

Relativamente às funcionalidades que o cliente temos as operações:
        
        PUT: ..
            Para executar basta selecionar no terminal do cliente. 
            Exemplo:
            5º Put
            6º caminho do ficheiro
            7º keywords que queremos atribuir a esse ficheiro
        LIST ..
            Para executar basta selecionar no terminal do cliente. Adicionalmente ele irá listar os ficheiros baseando-se no client_index de cada cliente de forma a que diferentes clientes apenas tenham              acesso aos seus              ficheiros.
            Exemplo:
            8º List
        GET .. 
            Para executar basta selecionar no terminal do cliente. Para recebermos o ficheiro de volta vamos fornecer o nome do ficheiro ao servidor.
            9º Get
            10º ficheiro.txt (exemplo)
        SEARCH
            Para executar esta funcionalidade basta selecionar no terminal do cliente e posteriormente fornecer o conjunto de keywords que queremos procurar separadas por ",".
            11º Search
            12º keyword1,keyword2
        EXIT
            Eventualmente se quisermos terminar a sessão do cliente basta selecionar esta opção.
            13º Exit

Quanto aos testes o cltest é feito dentro da pasta do Cliente por uma questão de Implementação (Questão discutida com o professor em aula). Visto que a lógica dos clientes prevalece nos Ids e palavras passes, decidimos que os comandos de teste vão incluir estes parametros para este teste.
    
    Exemplo de todos os comandos de teste:
    PUT: $ java cltest -id 1904 -pwd StrongPass123! PUT clientfiles/ficheiroteste.txt "keyword1,keyword2,keyword3"
    LIST: $ java cltest -id 1904 -pwd StrongPass123! LIST
    SEARCH: $ java cltest -id 1904 -pwd StrongPass123! SEARCH keyword1
    GET:
        Variante 1: $ java cltest -id 1904 -pwd StrongPass123! GET FILE relatorio.pdf .
        Variante 2: $ java cltest -id 1904 -pwd StrongPass123! GET KEYWORDS "financas" .
        Variante 3: $ java cltest -id 1904 -pwd StrongPass123! GET CHECKINTEGRITY relatorio.pdf
