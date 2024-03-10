import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto, UpdateAuthDto, RegisterUserDto, LoginDto } from './dto';
import { User } from './entities/user.entity';
import { InjectModel } from '@nestjs/mongoose';
import { Document, Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(@InjectModel(User.name) 
              private userModel : Model<User>,
              private jwtService : JwtService
              ){}

  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel( {
        password: bcryptjs.hashSync(password, 10),
        ...userData
      } )

      await newUser.save();

      const { password:_, ...user} = newUser.toJSON();

      return user
      
    } catch (error) {
      if(error.code === 11000){
        throw new BadRequestException(`${ createUserDto.email } already exists`)
      }

      throw new InternalServerErrorException('Internal error')
    }
    
  }

  async register(registeruserDto: RegisterUserDto):Promise<LoginResponse>{

      const user = await this.create(registeruserDto);

      return {
        user,
        token: this.getJwt( { id: user._id } )
      }
      
  }

  async login(loginDto: LoginDto):Promise<LoginResponse>{

    const {email, password } = loginDto;

    const user = await this.userModel.findOne({ email })

    if(!user) throw new UnauthorizedException('Not valid credentials')

    if( !bcryptjs.compareSync( password, user.password)) throw new UnauthorizedException('Not valid credentials')
    
    const { password:_, ...rest } = user.toJSON();
  

    return {
      user: rest,
      token: this.getJwt({ id: user._id })
    }

  } 

  findAll() : Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById( id:string ){
    const user = await this.userModel.findById(id).lean()
    const { password, ...rest } = user;
    return rest; 
  }

  findOne(id: string) {
    return this.userModel.findById(id)
    
  }

  update(id: string, updateAuthDto: UpdateAuthDto) {
      this.userModel.findById(id)
              .then(user => {
                if(user){
                  user.set(updateAuthDto)
                  user.save()
                }
              } )
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload){
    return this.jwtService.sign(payload);
  }

}
