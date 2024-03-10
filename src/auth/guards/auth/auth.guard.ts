import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from 'src/auth/auth.service';
import { JwtPayload } from 'src/auth/interfaces/jwt-payload';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor( private jwtService: JwtService,
                private authService: AuthService ){}

  async canActivate( context: ExecutionContext ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);
    
    if(!token) throw new UnauthorizedException();
    try {

      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
      )

      const user = await this.authService.findUserById(payload.id)

      if( !user ) throw new UnauthorizedException('User not found');
      if( !user.isActive ) throw new UnauthorizedException("User is not active");

      request['user'] = user;
      
    } catch (error) {
      console.log(error)
      throw new UnauthorizedException("Wrong token")
    }

    return Promise.resolve(true);
  }


  private extractTokenFromHeader(request: Request):string | undefined {
    console.log(request.headers)
    const [ type, token ] = request.headers['authorization']?.split(' ') ?? [];
    return type === "Bearer" ? token : undefined;
  } 
} 
