# 前提
解决需求前，通过.ai/human.md获取项目约束条件和领域对象描述，human.md的描述大于代码，有冲突时，使用askUserTool像用户进行提问。
修改文件夹下如果有human.md 也需要读取，.ai/human.md 约束 小于 模块内 human.md 但是大于实际code实现，使用askUserTool像用户进行确认 

# 开发流程
- 提交代码前，调用code-reviewer skill对提交的代码进行reviewer
- 不要加注释
- agents禁止修改human.md
