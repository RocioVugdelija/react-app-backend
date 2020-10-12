import express from 'express';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import bearerToken from 'express-bearer-token';
import bodyParser from 'body-parser';
import httpStatus from 'http-status';
import { users, ClientUser } from './users';
import { TokenPayload } from './token-payload.interface';
import cors from 'cors';

const app = express();
const port = 3001;

app.use(bearerToken());
app.use(bodyParser.json());
app.use(cors());
const privateKey = fs.readFileSync('./private.key', 'utf-8');
const publicKey = fs.readFileSync('./public.key', 'utf-8');


app.post('/api/v0/authenticate', (req, res) => {

  //Trae un usuario que coincida con las credenciales. Si no los hay, devuelve undefined
  let user = users.find(user => user.email === req.body.email && user.password === req.body.password);

  //Crea un token con la información del user, y lo retorna en el body de la respuesta
  if (user) {

    const tokenPayload: TokenPayload = {
      email: user.email
    };
    const token = jwt.sign(tokenPayload, privateKey, {
      algorithm: 'RS256',
      noTimestamp: true
    }
    );
    res.status(httpStatus.OK).send({
      jwt: token
    });
  }

  //Si las credenciales no coinciden con ningún user registrado, da un error general (sin especificar si es en la password o en el nombre por temas de seguridad)
  else {
    res.status(httpStatus.NOT_FOUND).send({
      message: "The email and password do not match"
    });
  }

});

/* Endpoint para manejar requests para la información del usuario
 * Verifica que el token de acceso exista y sea válido y retorna la data del usuario excepto la contraseña
 *Si la verificación falla, retorna un error
 */
app.get('/api/v0/users/me', (req, res) => {

  //Envía un error si el token de acceso del request es undefined
  if (req.token === undefined) {
    res.status(httpStatus.UNAUTHORIZED).send({
      message: "No access token provided"
    });
    return;
  }
  try {
    // Extrae el token de acceso del request
    const tokenPayload = <TokenPayload>jwt.verify(req.token, publicKey, {
      algorithms: ['RS256']
    });

    //Trae la información del usuario cuyo email coincide con el que trae el tocken. N
    const serverUser = users.find(user => user.email === tokenPayload.email);

    //Da un error si el usuario no existe
    if (serverUser === undefined) {
      res.status(httpStatus.NOT_FOUND).send({
        message: "User does not exist"
      });
    }

    //Cambia el tipo de usuario retornado para no enviar la contraseña
    else {
      const clientUser: ClientUser = {
        age: serverUser.age,
        avatar: serverUser.avatar,
        email: serverUser.email,
        id: serverUser.id,
        name: serverUser.name,
        role: serverUser.role,
        surname: serverUser.surname
      }
      res.status(httpStatus.OK).json(clientUser);
    }

  } //Da un error si el token es inválido y no puede verificarlo
  catch {
    res.status(httpStatus.UNAUTHORIZED).send({
      message: "Invalid Token provided"
    });
  }

});

/* Levanta el server y escucha al puerto elegido para las requests entrantes 
 */
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
})
