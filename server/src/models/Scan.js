import mongoose from 'mongoose';
const finding=new mongoose.Schema({id:String,title:String,severity:String,description:String,evidence:String,remediation:String},{_id:false});
const schema=new mongoose.Schema({owner:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true,index:true},target:{type:mongoose.Schema.Types.ObjectId,ref:'Target',required:true,index:true},url:String,status:{type:String,enum:['queued','running','completed','partial','inconclusive','failed'],default:'queued'},score:Number,grade:String,findings:[finding],checks:[{name:String,status:String,detail:String}],error:String,startedAt:Date,finishedAt:Date},{timestamps:true});
export default mongoose.model('Scan',schema);
