// Al estar habilitado el type: Module (sistema de Modulos) en el ECMAS No es posible usar la constante __dirname (esta definida para common.js)
// POR TANTO debemos crear a MANO las constantes necesarias para que funcione LAS RUTA ABSOLUTAS y luego exportarlas

// Creando los const ABSOLUTOS que me permiten tener PATH ABSOLUTAS = rutas absolutas

// importa todas las url de 'url' (trabajamos con todos las funciones prefabricadas en el modulo 'url')
import * as url from 'url'

export const __filename = url.fileURLToPath(import.meta.url)
export const __dirname = url.fileURLToPath(new URL('.', import.meta.url))

// Se debe importar del otro lado con los NOMBRES ESPECIFICOS DE LAS CONSTANTES (No se pues cambiar el nomnbre de la constante al importarlo)

// NOTA IMPORTANTE: el archivo utils.js NOS MUESTRA COMO SE DEBE EXPORTA UNA CONSTANTE cuando NO usamos export default


// --------------------------------------------// 

import bcrypt from 'bcrypt'// Importamos en utils el MODO bcrypt y sus  Funcionalidades

// Aca creamos 2 funciones Helpers para exportar usando los metodo que contiene el modulo bcrypt

// 1) LA PRIMERA para Hashaer el password que nos pasa usuario y NO pasarlo a la BD como texto plano
// Usamos el metodo hashSync de bcrypt para hashear la clave
export const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10))

// 2 LA SEGUNDA: Usamos el metodo compareSync de bcrypt para comparar el password ya hashead guardado en la BD
// y lo compara con el el password sin hashear del usurio  
// Devolvera true o false dependiendo si el password coincide o no 
// le pasamos el usuario de db y el password que llego del client
export const isValidPassword = (passwordInBody, passwordInBD) => bcrypt.compareSync(passwordInBody, passwordInBD)

// --------------------------------------------// 

// Trabajando con JWT (jsonWebToken) - Standard para la Autenticacion de Sessiones mediante CREDENCIALES 

// Importanto el Modulo
import jwt from 'jsonwebtoken'
import passport from 'passport' // Rutina de intercepción de errores para passport con JWT

// Este private key es para cifrar/firmar el token
const PRIVATE_KEY = 'JWT-Backend_Key_Jwt'

// Aca creamos 3 funciones:

// 1) Funciona para Crear el JWT 
// Esta funcion se usa al momento del login del usuario como un middleware 
// En lugar de generar una sesion, Generamos un token en el endpoint: /api/sessions/login
// payload = user (carga util datos del USUARIO INJERTADOS EN EL JWT que usaremos despues para validar)
export const generateToken = (payload, duration) => jwt.sign({ payload }, PRIVATE_KEY, { expiresIn: duration })


// 2) Funcion para Verificar y Validar el token Creado - Hecho a Mano para Validar sin Passport
export const authToken = (req, res, next) => {

    // verificando lo que llega en la query
    //console.log('authToken - ' ,req)

    // Esta constante tiene dentro una validacion ternanria (ESTUDIAR BIEN ESTO)
    // OJO: Explicando el Ternario que Uso el profe
    // req.headers.authorization !== undefined, indica que SI el JWT NO me llega por el hearder de la request
    // Entonces usa el JWT que me viene por la req.query

    // __________ IMPORTATE Mejorando la Recepcion del Token _____________

    // Caso 1 si viene por el req.headers
    const headerToken = req.headers.authorization ? req.headers.authorization.split(' ')[1] : undefined;

    // Caso 2 si viene por el req.cookie
    const cookieToken = req.cookies && req.cookies['cookie-JWT'] ? req.cookies['cookie-JWT'] : undefined;

    // Caso 3 si viene por el req.query
    const queryToken = req.query.access_token ? req.query.access_token : undefined;

    // Usamos el OR para que siempre entre alguno de los casos 
    // Tiene 3 Opciones para Extraer el Token 
    const receivedToken = headerToken || cookieToken || queryToken

    // if (!receivedToken) return res.status(401).send({ status: 'ERR', data: 'No autenticado' })

    // SiNO estoy recibiendo ningun TOKEN redirecciono a /login 
    if (!receivedToken) return res.redirect('/login')

    // Como si RECIBI EL TOKEN entonces lo valido 
    jwt.verify(receivedToken, PRIVATE_KEY, (err, credentials) => {

        console.log('jwt.verify', credentials)
        //console.log('jwt.verify', err)

        // Si el token no es validdo o expiro su tiempo envio .send({ status: 'ERR', data: 'No autorizado' })
        if (err) return res.status(403).send({ status: 'ERR', data: 'No autorizado' })

        // Si todo esta bien guardo la credenciales 
        req.user = credentials

        // salgo del middleware y sigo con el endpoint que corresponde
        next()
    })
}


// 3) Rutina de Intercepción de errores Mejorada para passport
// Esta funcion la estaremos usando como un middleware en la rutas (endpoints)
export const passportCall = (strategy, options) => {

    // console.log(strategy, options)
    // Retorna un Callback Asincrono 
    return async (req, res, next) => {

        //console.log(req)

        //Dentro de la Callback uso la estrategia de passport
        passport.authenticate(strategy, options, (err, user, info) => {

            // Aca se hace una Captura de errores mas optima 
            // Para Mejorar los Mensajes de Error 
            if (err) return next(err);
            if (!user) return res.status(401).send({ status: 'ERR-', data: info.messages ? info.messages : info.toString() });

            // Sino Existen errores Asigno el user al req.user y sigo next();
            // Seteamos el usuario y sigue el next();
            req.user = user;
            next();

        })(req, res, next);
    }
}