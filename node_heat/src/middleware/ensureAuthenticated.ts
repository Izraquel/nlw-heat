import { Request, Response, NextFunction, request} from 'express'
import { verify } from 'jsonwebtoken'

interface IPayload {
    sub: string;
} 

export function ensureAuthenticated(req: Request, res: Response, next: NextFunction) {
    const authToken = req.headers.authorization;

    if(!authToken) {
        return res.status(401).json({
            errorCode: "token.invalid"
        });
    }

    //Bearer 8787hgyi4r54tge4rt5e4rt84ert5d5tw4r5
    // [0] Bearer
    // [1] 8787hgyi4r54tge4rt5e4rt84ert5d5tw4r5

    const [,token] = authToken.split(" ") //split- separa string

    try { 
        const { sub } = verify(token, process.env.JWT_SECRET) as IPayload;

        req.user_id = sub;

        return next();

    }catch(err){
        return res.status(401).json({errorCode: "token.expired"})
    }

}
