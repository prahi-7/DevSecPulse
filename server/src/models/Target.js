import mongoose from 'mongoose';
const schema=new mongoose.Schema({owner:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true,index:true},name:{type:String,required:true,maxlength:100},url:{type:String,required:true,maxlength:2048}},{timestamps:true});
export default mongoose.model('Target',schema);
