import datetime
import asyncio
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger


class DiaryPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        super().__init__(context)
        self.config = config or {}
        self.plugin_id = "astrbot_plugin_diary"
        self.lock = asyncio.Lock()

    async def _get_and_migrate_index_locked(
        self, umo: str, persona_id: str
    ) -> list[str]:
        index_key = f"diary_index_{umo}_{persona_id}"
        old_kv_key = f"diaries_{umo}_{persona_id}"

        dates = await self.get_kv_data(index_key, default=[])
        if dates:
            return dates

        # Migrate old data if it exists
        dates = []
        old_data = await self.get_kv_data(old_kv_key, default={})
        if isinstance(old_data, dict):
            for d, content in old_data.items():
                dates.append(d)
                await self.put_kv_data(f"diary_content_{umo}_{persona_id}_{d}", content)
            await self.delete_kv_data(old_kv_key)

        await self.put_kv_data(index_key, dates)
        return dates

    async def _get_index(self, umo: str, persona_id: str) -> list[str]:
        async with self.lock:
            return await self._get_and_migrate_index_locked(umo, persona_id)

    async def _add_to_index(self, umo: str, persona_id: str, date_str: str):
        index_key = f"diary_index_{umo}_{persona_id}"
        async with self.lock:
            dates = await self._get_and_migrate_index_locked(umo, persona_id)
            if date_str not in dates:
                dates.append(date_str)
                await self.put_kv_data(index_key, dates)

    async def _remove_from_index_or_clear(
        self, umo: str, persona_id: str, date_str: str
    ) -> bool:
        """返回是否成功"""
        index_key = f"diary_index_{umo}_{persona_id}"
        async with self.lock:
            dates = await self._get_and_migrate_index_locked(umo, persona_id)
            if date_str.lower() == "all":
                for d in dates:
                    await self.delete_kv_data(f"diary_content_{umo}_{persona_id}_{d}")
                await self.delete_kv_data(index_key)
                return True

            if date_str in dates:
                dates.remove(date_str)
                await self.put_kv_data(index_key, dates)
                await self.delete_kv_data(
                    f"diary_content_{umo}_{persona_id}_{date_str}"
                )
                return True
            return False

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

        default_prompt = (
            "你正在扮演：{persona_prompt}\n"
            "以下是今天的对话内容：\n{history_str}\n"
            "请根据以上内容，以该角色的口吻写一篇今日日记。\n要求：\n"
            "1. 仅限使用以下三种 Markdown 格式来表现角色的心理波动（严禁使用其他复杂的Markdown格式如代码块等）：\n"
            "   - 加粗 (**文字**)：用于角色觉得非常重要的事情\n"
            "   - 斜体 (*文字*)：用于显示角色比较阴暗的、觉得不应该告诉用户的想法\n"
            "   - 删除线 (~~文字~~)：用于角色回想后觉得羞耻的内容\n"
            "2. 内容贴合实际发生的对话，可以透露一些只有角色知道而用户不知道的事情\n"
            "3. 语言风格符合角色设定，日记内容需要体现角色的心理活动\n"
            "4. 日记总字数应在812-1201字区间"
        )
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
                "diary_fail_error_msg",
                "生成日记时出现错误，请联系管理员或查看后台日志。",
            )
            yield event.plain_result(err_msg_template.replace("{e}", str(e)))
            return

        # 3. Save to KV
        today_str = datetime.datetime.now().strftime("%Y-%m-%d")
        content_key = f"diary_content_{umo}_{persona_id}_{today_str}"

        await self.put_kv_data(content_key, diary_content)
        await self._add_to_index(umo, persona_id, today_str)

        # 4. Reply
        yield event.plain_result(f"【{today_str} 日记】\n\n{diary_content}")

    @filter.command("查看日记列表")
    async def list_diaries(self, event: AstrMessageEvent):
        """查看AI写过的日记的日期列表"""
        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)

        dates = await self._get_index(umo, persona_id)
        if not dates:
            yield event.plain_result("该人格目前还没有写过日记哦。")
            return

        dates.sort(reverse=True)
        msg = "该人格的日记列表如下：\n" + "\n".join(dates)
        msg += "\n\n可以使用 /阅读日记 [日期] (如: /阅读日记 2023-10-27) 来阅读具体某天的日记哦！"
        yield event.plain_result(msg)

    @filter.command("阅读日记")
    async def read_diary(self, event: AstrMessageEvent, date_str: str):
        """阅读具体某天的日记，参数为日期"""
        try:
            datetime.datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            yield event.plain_result(
                "日期格式错误，请使用 YYYY-MM-DD 格式，例如 2023-10-27。"
            )
            return

        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)

        dates = await self._get_index(umo, persona_id)
        content_key = f"diary_content_{umo}_{persona_id}_{date_str}"

        if date_str in dates:
            content = await self.get_kv_data(content_key, default="")
            yield event.plain_result(f"【{date_str} 日记】\n\n{content}")
        else:
            yield event.plain_result(
                f"未找到 {date_str} 的日记。请使用 /查看日记列表 确认日期。"
            )

    @filter.command("删除日记")
    async def delete_diary(self, event: AstrMessageEvent, date_str: str):
        """删除特定日期日记，参数为日期或all"""
        if date_str.lower() != "all":
            try:
                datetime.datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                yield event.plain_result(
                    "日期格式错误，请使用 YYYY-MM-DD 格式，例如 2023-10-27。"
                )
                return

        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)

        success = await self._remove_from_index_or_clear(umo, persona_id, date_str)
        if success:
            if date_str.lower() == "all":
                yield event.plain_result("已清空该人格的所有日记。")
            else:
                yield event.plain_result(f"已删除 {date_str} 的日记。")
        else:
            yield event.plain_result(
                f"未找到 {date_str} 的日记。请使用 /查看日记列表 确认日期。"
            )
