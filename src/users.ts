//Normalmente separaría las dos interfaces en distintos documentos, pero los dejo para seguir las condiciones del ejercicio
export interface ClientUser {
	id: string;
	avatar: string;
	age: number;
	email: string;
	name: string;
	role: 'admin' | 'user'
  	surname: string;
}

export interface ServerUser extends ClientUser {
	password: string;
}

export const users: ServerUser[] = [{
	id: "it-drixit-1",
	avatar: "https://toppng.com/uploads/preview/roger-berry-avatar-placeholder-11562991561rbrfzlng6h.png",
	email: "it@drixit.com",
	password: "some-password",
	name: "IT",
	surname: "Drixit",
	age: 25,
	role: "admin"
}, {
	id: "info-drixit-2",
	avatar: "https://toppng.com/uploads/preview/roger-berry-avatar-placeholder-11562991561rbrfzlng6h.png",
	email: "info@drixit.com",
	password: "other-password",
	name: "Info",
	surname: "Drixit",
	age: 30,
	role: "user"
}];
