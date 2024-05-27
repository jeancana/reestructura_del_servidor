// Verificando lo que me esta llegando por el Objeto "process" 
//console.log(process.argv) 

// Le pido al Objeto process que me muestre los contiene en su atributo .argv (argumento) 
// ES un Array de Argumentos de Lineas de Comando 
// El 1er elemento: es la ruta donde esta el ejecutable de Node
// El 2do elemento: es la ruta la app (aplicacion) que esta ejecutando Nodemon
// Nota: 1er y 2do siempre son los mismo (NO CAMABIAN NUNCA) - los crea el sistema
// "voy a agregar mas elementos (Agregare mas lineas de comando)"


// Paso 1: importo el modulo Commander y Parsea todas las Lineas de Comando en un Objeto 
import { Command } from 'commander'; //Permite parsear CLI (opciones de linea de comando) 

// Paso 1: APROVECHANDO LAS VARIABLES DE ENTORNO para Proteger DATOS SENSIBLES
// Me permite guardar bien informacion sensible de las autenticaciones 
// Toda Informacion Sensible debe Ser GUARDADA EN VARIABLES DE ENTORNO 
// Todo lo que esta en passport.auth etc etc...
import dotenv from 'dotenv'; // Permite el Manejo de Variables de Entorno dentro de ambito de trabajo


// ----- CREANDO ARGUMENTO DE LINEAS DE COMANDO PERSONALIZADOS --------

// IMPORTANTE en el package.json creo "--mode=dev --port=5000" (2 opciones de lineas de comando nuevas)
// Estoy agregando al array de Argumentos de Lineas de Comando 2 lineas de comando Nuevas  
// que utilizare en el archivo 

// ----- Habilitando la nuevas opciones de CLI creadas por mi desde el package.json

// *** Forma 1: Sencilla de hacerlo
// Uso el metodo slice(2) que descarta los 2 primeros elementos del Array original 
// Y solo tener el el array las lineas de comando creadas por mi 
//const commandLineOptions_ = process.argv.slice(2)
//console.log('CL haciendolo a Pie', commandLineOptions_)// Verificando que las CL creadas por mi esten en el array 


// *** Forma 2: Usando el Modulo Importado Commander 
// -- Commander es un modulo practico para parseo de opc. de lineas de comando 
const commandLineOptions = new Command() // Crea una nueva instancia del Modulo 'commander'

// Aca le indico las opciones que deseo Captar al commandLineOptions 

commandLineOptions
    .option('--mode <mode>')// Estamos encadenando Metodos 
    .option('--port <port>')// Estamos encadenando Metodos 
    // Aca podemos agregar todas las opciones que deseamos parsear a objetos

commandLineOptions.parse()// PARSEANDO EN UN OBJETO TODAS LAS LINEAS DE COMANDO PERSONALIZADAS CREADAS

// Verificando las opciones LINEAS DE COMANDO PERSONALIZADOS agragedas como opciones 
// se lo pedimos al commandLineOptions.opts()
//console.log('CL Usando commander', commandLineOptions.opts())//Verificando que las CL creadas por mi esten en el array 

// IMPORTANTE: a partir de ahora somo capaces de leer opciones de Lineas de comando desde el "scritp"
// de Package.json 


/**
 * CREANDO EL OBJETO CONFIG - que seran exportado 
 * __Nota: Aca voy tener Todas las configuraciones de acceso a la BBDD 
 * Ya no van a estar hardcodeadas en el app.js
 * Combinando variables de entorno, opciones de línea de comandos y valores fijos,
 * armamos nuestro objeto config, que importaremos para usar en cualquier archivo
 * de nuestro proyecto.
 */


// USANDO EL  OBJETO CONFIG 
// Ahora las distintas conexiones se van manejar desde al objeto config

// *** Forma 1: Sencilla de hacerlo
/* const config = {

    // Declarando el Puerto de Conexion 
    PORT: 5000,
    //Conectando con la BD Local - MONGO COMPAS
    MONGOOSE_URL: 'mongodb://127.0.0.1:27017/coder_55605' 

}; */


// *** Forma 2: Aprovechando las commandLineOptions y Usando el modulo dotenv
// --- OPCION 1:  Haciendolo a MANO Como lo Hago a mano se complica un poco en Mac 
//console.log(' Se resuelve con el modulo dotenv...', process.env.MONGOOSE_URL) // le pido al Objeto process que variable de entorno tengo disponibles 

// --- OPCION 2: Usando el Modulo de dotenv importado 
// Activamos la Variables de entorno creadas en el archivo .env
// Le indicamos la ruta donde van a estar alojadas las variables de entorno 
dotenv.config({path: './.env'})
//console.log('Verifico que dotenv Inyecto las V de Entorno...', process.env.MONGOOSE_URL_LOCAL)

//console.log(process.env.PORT)

// Objeto config
const config = {


    // Ahora podemos leer opciones de lineas de Comando
    PORT: commandLineOptions.opts().port || process.env.PORT, //Uso CL personalizada --port y la V de Entorno

    //Conectando con la BD Local - MONGO COMPAS
    MONGOOSE_URL_LOCAL: process.env.MONGOOSE_URL_LOCAL,

    //Conectando con la BD Remota en la NUBE - MONGO ATLAS
    MONGOOSE_URL_REMOTE: process.env.MONGOOSE_URL_REMOTE,

    // CREO UN OBJ dentro del Obj config - Para Confirgurar la Autenticacion de GitHub con Variables de entorno
    GITHUB_AUTH: {
        clientId: process.env.GITHUB_AUTH_CLIENT_ID,
        clientSecret: process.env.GITHUB_AUTH_CLIENT_SECRET,
        // Atención!: si bien podemos rearmar la url de callback acá con el puerto que deseemos,
        // debemos estar atentos a actualizarla también en la config de la app que hemos activado en Github
        callbackUrl: `http://localhost:${commandLineOptions.opts().port}/api/sessions/githubcallback`
    },
 

     GOOGLE_AUTH: {
        clientId: process.env.GOOGLE_AUTH_CLIENT_ID,
        clientSecret: process.env.GOOGLE_AUTH_CLIENT_SECRET,
        // Atención!: si bien podemos rearmar la url de callback acá con el puerto que deseemos,
        // debemos estar atentos a actualizarla también en la config de la app que hemos activado en Google
        callbackUrl: `http://localhost:${commandLineOptions.opts().port}/api/sessions/googlecallback`
    }

};


export default config;