import datetime
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api import logger


@register("astrbot_plugin_diary", "YourName", "AI日记插件", "1.0.0")
class DiaryPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        super().__init__(context)
        self.config = config or {}
        self.plugin_id = "astrbot_plugin_diary"

    async def _get_persona_info(self, event: AstrMessageEvent) -> tuple[str, str]:
        umo = event.unified_msg_origin
        persona_id = "default"
        persona_prompt = "You are a helpful assistant."

        try:
            if hasattr(self.context, "persona_manager") and hasattr(
                self.context.persona_manager, "resolve_selected_persona"
            ):
                (
                    pid,
                    persona,
                    _,
                    _,
                ) = await self.context.persona_manager.resolve_selected_persona(
                    umo=umo,
                    conversation_persona_id=None,
                    platform_name=event.get_platform_name(),
                )
                if pid:
                    persona_id = pid
                if persona:
                    persona_prompt = persona.get("prompt", persona_prompt)
            else:
                curr_cid = (
                    await self.context.conversation_manager.get_curr_conversation_id(
                        umo
                    )
                )
                if curr_cid:
                    conv = await self.context.conversation_manager.get_conversation(
                        umo, curr_cid
                    )
                    if conv and conv.persona_id:
                        persona_id = conv.persona_id

                if hasattr(self.context, "provider_manager") and hasattr(
                    self.context.provider_manager, "personas"
                ):
                    for p in self.context.provider_manager.personas:
                        if p.get("name") == persona_id:
                            persona_prompt = p.get("prompt", persona_prompt)
                            break
        except Exception as e:
            logger.error(f"Error resolving persona: {e}")

        return persona_id, persona_prompt

    @filter.command("今日日记")
    async def today_diary(self, event: AstrMessageEvent):
        """让AI根据今日上下文写一篇日记"""
        writing_msg = self.config.get(
            "diary_writing_msg", "正在为您撰写日记中，这可能需要一点时间，请稍候..."
        )
        yield event.plain_result(writing_msg)

        umo = event.unified_msg_origin

        # 1. 获取 persona
        persona_id, persona_prompt = await self._get_persona_info(event)

        # 2. 获取 history
        curr_cid = await self.context.conversation_manager.get_curr_conversation_id(umo)
        history_str = ""
        if curr_cid:
            (
                contexts,
                _,
            ) = await self.context.conversation_manager.get_human_readable_context(
                umo, curr_cid, page=1, page_size=100
            )
            if contexts:
                # contexts page 1 返回的是最新的聊天记录，按倒序排列（新到旧）。这里翻转为时间顺序（旧到新）。
                contexts.reverse()
                history_str = "\n".join(contexts)

        if not history_str:
            history_str = self.config.get(
                "diary_no_history_msg", "今日暂无有意义的对话记录。"
            )

        default_prompt = "你正在扮演：{persona_prompt}\n以下是今天的对话内容：\n{history_str}\n请根据以上内容，以该角色的口吻写一篇今日日记。\n要求：\n1. 使用 Markdown 格式（如删除线、加黑等）用于表现角色的心情波动，如觉得羞耻的内容会用删除线标记，阴暗的想法会用加黑标记，很重要的事情使用加粗标记。\n2. 内容贴合实际发生的对话，可以透露一些只有角色知道而用户不知道的事情\n3. 语言风格符合角色设定，日记内容需要体现角色的心理活动\n4. 日记总字数应在812-1201字区间"
        prompt_template = self.config.get("diary_prompt", default_prompt)

        try:
            prompt = prompt_template.format(
                persona_prompt=persona_prompt, history_str=history_str
            )
        except Exception as e:
            logger.error(f"日记模板格式化失败，将使用默认模板。原因: {e}")
            prompt = default_prompt.format(
                persona_prompt=persona_prompt, history_str=history_str
            )

        chat_provider_id = await self.context.get_current_chat_provider_id(umo)
        try:
            llm_response = await self.context.llm_generate(
                chat_provider_id=chat_provider_id,
                prompt=prompt,
                system_prompt=persona_prompt,
            )

            if not llm_response or not llm_response.completion_text:
                fail_msg = self.config.get(
                    "diary_fail_no_reply_msg", "生成日记失败，模型未返回回复。"
                )
                yield event.plain_result(fail_msg)
                return

            diary_content = llm_response.completion_text
        except Exception as e:
            logger.error(f"生成日记失败: {e}")
            err_msg_template = self.config.get(
                "diary_fail_error_msg", "生成日记时出现错误: {e}"
            )
            yield event.plain_result(err_msg_template.replace("{e}", str(e)))
            return

        # 3. Save to KV
        kv_key = f"diaries_{umo}_{persona_id}"
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")

        diaries = await self.get_kv_data(kv_key, default={})
        diaries[today_str] = diary_content
        await self.put_kv_data(kv_key, diaries)

        # 4. Reply
        yield event.plain_result(f"【{today_str} 日记】\n\n{diary_content}")

    @filter.command("查看日记列表")
    async def list_diaries(self, event: AstrMessageEvent):
        """查看AI写过的日记的日期列表"""
        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)
        kv_key = f"diaries_{umo}_{persona_id}"

        diaries = await self.get_kv_data(kv_key, default={})
        if not diaries:
            yield event.plain_result("该人格目前还没有写过日记哦。")
            return

        dates = list(diaries.keys())
        dates.sort(reverse=True)
        msg = "该人格的日记列表如下：\n" + "\n".join(dates)
        msg += "\n\n可以使用 /阅读日记 [日期] (如: /阅读日记 2023-10-27) 来阅读具体某天的日记哦！"
        yield event.plain_result(msg)

    @filter.command("阅读日记")
    async def read_diary(self, event: AstrMessageEvent, date_str: str):
        """阅读具体某天的日记，参数为日期"""
        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)
        kv_key = f"diaries_{umo}_{persona_id}"

        diaries = await self.get_kv_data(kv_key, default={})
        if date_str in diaries:
            yield event.plain_result(f"【{date_str} 日记】\n\n{diaries[date_str]}")
        else:
            yield event.plain_result(
                f"未找到 {date_str} 的日记。请使用 /查看日记列表 确认日期。"
            )

    @filter.command("删除日记")
    async def delete_diary(self, event: AstrMessageEvent, date_str: str):
        """删除特定日期日记，参数为日期或all"""
        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)
        kv_key = f"diaries_{umo}_{persona_id}"

        if date_str.lower() == "all":
            await self.delete_kv_data(kv_key)
            yield event.plain_result("已清空该人格的所有日记。")
            return

        diaries = await self.get_kv_data(kv_key, default={})
        if date_str in diaries:
            del diaries[date_str]
            await self.put_kv_data(kv_key, diaries)
            yield event.plain_result(f"已删除 {date_str} 的日记。")
        else:
            yield event.plain_result(
                f"未找到 {date_str} 的日记。请使用 /查看日记列表 确认日期。"
            )
