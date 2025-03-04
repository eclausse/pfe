import Controller from "./controller";
import { NextFunction, Request, Response, Router } from "express";
import { Database } from "sqlite3";
import { log } from "console";
import { createHash, randomUUID, UUID } from "crypto";
import dotenv from "dotenv";

dotenv.config();

class AdminController implements Controller {
  static path = "/admin";
  router: Router;
  db_name = "vuln.db";

  constructor() {
    this.router = Router();
    //this.router.use(this.verifyBackendAccess); /* Middleware to verify backend access */
    this.router.get(AdminController.path, this.get); 
  }

  static run_query(query: string, params: any = []) {
    const db = new Database("vuln.db");
    return new Promise((resolve, reject) =>
      db.all(query, params, (err, rows) => {
        if (err) {
          console.log(err);
        }
        resolve(rows);
      })
    );
  }

  async get(req: Request, res: Response) {
    const backendToken = req.headers['x-backend-token'];
    console.log(backendToken + " " + process.env.BACKEND_TOKEN);

    if (backendToken != process.env.BACKEND_TOKEN) {
      res.status(403).send("Forbidden");
    }

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Panel</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f4f4f4;
          }
          .container {
            text-align: center;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
          }
          h1 {
            margin-bottom: 20px;
          }
          button {
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            border: none;
            border-radius: 5px;
            background-color:rgb(255, 72, 0);
            color: white;
          }
          button:hover {
            background-color:rgb(255, 0, 0);
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Admin Panel</h1>
          <p>Welcome to the admin panel.</p>
          <button onclick="alert('Admin action executed')">Shutdown!</button>
        </div>
      </body>
      </html>
    `;
    res.send(html);
  }
}

export default AdminController;