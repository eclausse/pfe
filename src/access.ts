import Controller from "./controller";
import { Request, Response, Router } from "express";
import { Database } from "sqlite3";
import { log } from "console";
import { createHash, randomUUID, UUID } from "crypto";
import UserController from "./user";

class AccessController implements Controller {
  static path = "/access";
  router: Router;
  db_name = "vuln.db";

  constructor() {
    this.router = Router();
    this.router.get(AccessController.path, this.get); 

    this.router.post(AccessController.path, this.login);
    this.router.post(AccessController.path, this.login_fix);
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
    const sql: string = `SELECT * FROM access`;
    let access: String[][] = [];
    await AccessController.run_query(sql).then((rows: any) =>
      rows.forEach((row: any) => {
        access.push([row.uid, row.access_token]);
      })
    );

    console.log(
      "[INFO][GET] get alls on " + AccessController.path,
      );
      // Envoi de la réponse
      res.send(JSON.stringify(access));  
  }

  async login(req: Request, res: Response) {
    const uid = req.body.uid;
    const password = req.body.password;

    if (uid === undefined) {
        res.send("Please provide an uid");
        return;
    }
    if (password === undefined) {
        res.send("Please provide a password");
        return;
    }

    // Check if user exists
    let sql = `SELECT * FROM user WHERE uid = ? AND password = ?`;
    let params = [uid, password];
    let user: String[] = [];
    // Passage de la requête et des paramètres à la fonction run_query
    await UserController.run_query(sql, params).then((rows: any) =>
        rows.forEach((row: any) => {
          user.push(row.uid);
        })
    );
    if (user.length === 0) {
        res.send("User not found");
        return;
    }

    const access_token: string = randomUUID().toString();
    sql = `INSERT INTO access (uid, access_token) VALUES ('${uid}', '${access_token}')`;
    await AccessController.run_query(sql);
    console.log(
      "[INFO][POST] insert on " + AccessController.path,
    );
    res.send(JSON.stringify(access_token));
  }

    async login_fix(req: Request, res: Response) {
        const uid = req.body.uid;
        const password = req.body.password;

        if (uid === undefined) {
            res.send("Please provide an uid");
            return;
        }
        if (password === undefined) {
            res.send("Please provide a password");
            return;
        }

        // Get hash of password
        const hash = createHash("sha256").update(password).digest("hex");
        console.log(hash);
        // Check if user exists
        let sql = `SELECT * FROM user WHERE uid = ? AND password = ?`;
        let params = [uid, hash];
        let user: String[] = [];
        // Passage de la requête et des paramètres à la fonction run_query
        await UserController.run_query(sql, params).then((rows: any) =>
            rows.forEach((row: any) => {
              user.push(row.uid);
            })
        );
        if (user.length === 0) {
            res.send("User not found");
            return;
        }

        const access_token: string = randomUUID().toString();
        sql = `INSERT INTO access (uid, access_token) VALUES ('${uid}', '${access_token}')`;
        await AccessController.run_query(sql);
        console.log(
          "[INFO][POST] insert on " + AccessController.path,
        );
        res.send(JSON.stringify(access_token));
    }
}

export default AccessController;
