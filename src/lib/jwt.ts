import { PrismaClient } from '@prisma/client';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';

type UserPayload = JwtPayload & {
  id: string;
  nom: string;
  prenom: string;
};

type VerifyResult = {
  valid: boolean;
  expired: boolean;
  decoded: UserPayload | null;
};

export class JWTManager {
  private secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  // Générer un jeton JWT
  generateToken(
    payload: UserPayload,
    expiresIn: string | number = '1h',
  ): string {
    const signOptions: SignOptions = { expiresIn };
    return jwt.sign(payload, this.secret, signOptions);
  }

  // Vérifier un jeton JWT
  verifyToken(token: string): VerifyResult {
    try {
      const decoded = jwt.verify(token, this.secret) as UserPayload;
      return { valid: true, expired: false, decoded };
    } catch (error) {
      return {
        valid: false,
        expired:
          error instanceof Error && error.message.includes('jwt expired'),
        decoded: null,
      };
    }
  }
}
