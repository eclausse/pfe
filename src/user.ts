import Controller from "./controller";
import { Request, Response, Router } from "express";
import { Database } from "sqlite3";
import { log } from "console";
import { createHash, randomUUID, UUID } from "crypto";

class UserController implements Controller {
  static path = "/user";
  router: Router;
  db_name = "vuln.db";

  constructor() {
    this.router = Router();
    this.router.get(UserController.path, this.get); /* Vulnérabilité SQLi */
    this.router.get(UserController.path + "/fix", this.get_with_parameterized_query); /* Pas de vulnérabilité SQLi*/
    this.router.get(UserController.path + "/:id", this.get_by_id); /* Pas de vulnérabilité SQLi*/
    this.router.post(UserController.path, this.post);
    this.router.put(UserController.path + "/:id", this.update_by_id);
  }

  static run_query(query: string, params: any = []) {
    const db = new Database("vuln.db");
    return new Promise((resolve, reject) =>
      db.all(query,params, (err, rows) => {
        if (err) {
          console.log(err);
        }
        resolve(rows);
      })
    );
  }

    async get(req: Request, res: Response) {
        // Vérification de la présence du paramètre name 
        if (req.body.name === undefined) {
            res.send("Please provide a name");
            return;
        }
        
        // Création de la requête SQL en concaténant le paramètre name
        const sql: string = `SELECT rowid, * FROM user WHERE name = "${req.body.name}"`; // SQL Injection possible
        // Récupération des utilisateurs en fonction de la requête
        let users: String[][] = [];
        await UserController.run_query(sql).then((rows: any) =>
            rows.forEach((row: any) => {
              users.push([row.uid, row.name, row.surname, row.password, row.is_admin]);
            })
        );

        console.log(
        "[INFO][GET] get alls on " + UserController.path,
        );
        // Envoi de la réponse
        res.send(JSON.stringify(users));  
    }

    async get_with_parameterized_query(req: Request, res: Response) {
      // Vérification de la présence du paramètre name 
      if (req.body.name === undefined) {
          res.send("Please provide a name");
          return;
      }
      
      // Création de la requête SQL parametriée
      const sql: string = `SELECT rowid, * FROM user WHERE name = @0`; // SQL Injection impossible
      const params = [req.body.name];

      // Récupération des utilisateurs en fonction de la requête
      let users: String[][] = [];
      // Passage de la requête et des paramètres à la fonction run_query
      await UserController.run_query(sql, params).then((rows: any) =>
          rows.forEach((row: any) => {
            users.push([row.name, row.surname, row.password, row.is_admin]);
          })
      );

      console.log(
      "[INFO][GET] get alls on " + UserController.path,
      );
      // Envoi de la réponse
      res.send(JSON.stringify(users));  
    }

    async get_by_id(req: Request, res: Response) {
      // Vérification de la présence du paramètre id 
      if (req.params.id === undefined) {
          res.send("Please provide an id");
          return;
      }

      // !!! Attention: Pas de vérification de la provenance de la requête HTTP !!!
      let sql: string = `SELECT * FROM access WHERE uid = ?`;
      let params = [req.params.id];
      let access_token: String = "";
      await UserController.run_query(sql, params).then((rows: any) =>
        rows.forEach((row: any) => {
          user.push(row.access_token);
        })
      );

      if (req.params.access_token != access_token) {
        res.send("Unauthorized access");
        return;
      }
      
      // Création de la requête SQL 
      sql = `SELECT * FROM user WHERE uuid = ?`;
      params = [req.params.id];

      // Récupération de l'utilisateur en fonction de la requête
      let user: String[] = [];
      // Passage de la requête et des paramètres à la fonction run_query
      await UserController.run_query(sql, params).then((rows: any) =>
          rows.forEach((row: any) => {
            user.push(row.uid, row.name, row.surname, row.password, row.is_admin);
          })
      );

      console.log("[INFO][GET] get id "+   req.params.id + " on " + UserController.path + " " +  user.toString());
      // Envoi de la réponse
      res.send(JSON.stringify(user));
    }
  
    async post(req: Request, res: Response) {
        //Hachage du mot de passe
        const password = req.body.password;
        const hashedPassword = createHash('sha256').update(password).digest('hex');

        const user = new UserEntry(
            randomUUID(),
            req.body.name,
            req.body.surname,
            hashedPassword,
            req.body.is_admin
        );
        console.log("ID = " + user.id);
        const sql = `INSERT INTO user (uid, name, surname, password, is_admin) VALUES ('${user.id}', '${user.name}', '${user.surname}', '${user.password}', ${user.is_admin})`;
        await UserController.run_query(sql);
        console.log(
        "[INFO][POST] insert on " + UserController.path,
        );
        res.send("User added successfully");
    }
    
    async update_by_id(req: Request, res: Response) {
      // Vérification de la présence du paramètre id 
      if (req.params.id === undefined) {
        res.send("Please provide an id");
        return;
      }
  
      const userId = req.params.id;
      const { name, surname, password, is_admin } = req.body;
  
      // Création de la requête SQL parametriée
      const sql: string = `UPDATE user SET name = ?, surname = ?, password = ?, is_admin = ? WHERE rowid = ?`; // SQL Injection impossible
      const params = [name, surname, password, is_admin, userId];
  
      await UserController.run_query(sql, params);
  
      console.log(
        "[INFO][PUT] update user by id on " + UserController.path,
      );
      res.send("User updated successfully");
    }
}

export default UserController;

class User {
  name: string;
  surname: string;
  password: string;
  is_admin: boolean;
  constructor(
    name: string,
    surname: string,
    password: string,
    is_admin: boolean
  ) {
    this.name = name;
    this.surname = surname;
    this.password = password;
    this.is_admin = is_admin;
  }
}

class UserEntry {
  id: UUID;
  name: string;
  surname: string;
  password: string;
  is_admin: boolean;

  constructor(
    id: UUID,
    name: string,
    surname: string,
    password: string,
    is_admin: boolean
  ) {
    this.id = id;
    this.name = name;
    this.surname = surname;
    this.password = password;
    this.is_admin = is_admin;
  }
}