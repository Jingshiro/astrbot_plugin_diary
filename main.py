import datetime
import asyncio
import json
import random
import string
import base64
from typing import Any
from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star
from astrbot.api import logger

import sys
import subprocess

MQTT_AVAILABLE = False
try:
    import paho.mqtt.client as mqtt
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import hashlib

    MQTT_AVAILABLE = True
except ImportError:
    logger.warning(
        "paho-mqtt or pycryptodome is not installed. Attempting auto-installation..."
    )
    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "paho-mqtt==2.1.0",
                "pycryptodome==3.20.0",
            ]
        )
        logger.info("Auto-installation successful. Importing modules...")
        import paho.mqtt.client as mqtt
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        import hashlib

        MQTT_AVAILABLE = True
    except Exception as e:
        logger.error(
            f"Auto-installation failed: {e}. WebUI will be disabled. Please run `pip install paho-mqtt pycryptodome` manually."
        )
        MQTT_AVAILABLE = False


def generate_random_string(length: int = 16) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


class AESCipher:
    def __init__(self, key: str):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw: str) -> str:
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(raw.encode("utf-8"), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ct = base64.b64encode(ct_bytes).decode("utf-8")
        # Simulate CryptoJS format: it often prepends Salted__ but we'll use a simple JSON format to match frontend or we can just stick to CryptoJS default.
        # However, to be perfectly compatible with CryptoJS AES default, we need to match WordArray.
        # Actually, matching CryptoJS AES default is simpler if we construct the OpenSSL format "Salted__" + salt + ciphertext, OR we just use another library.
        # Since frontend uses var bytes = CryptoJS.AES.decrypt(cipherText, secretKey);
        # The easiest way to be fully compatible with frontend's default CryptoJS is to let CryptoJS handle it by returning a JSON object or using EvpKDF.
        pass


# Since Python and CryptoJS AES default compatibility is complex, we will implement a custom simple encrypt/decrypt in Python and update the frontend if needed, OR we just use a known compatible method.
# For maximum simplicity and compatibility with the exact frontend code: CryptoJS.AES.decrypt(cipherText, secretKey);
# CryptoJS by default uses MD5 EvpKDF to derive Key & IV from the passphrase.
# We will implement EvpKDF.
def evp_kdf(password: bytes, salt: bytes, key_len: int, iv_len: int):
    d = d_i = b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len : key_len + iv_len]


class CryptoJS_AES:
    @staticmethod
    def encrypt(data_str: str, passphrase: str) -> str:
        salt = bytes(random.choices(range(256), k=8))
        key, iv = evp_kdf(passphrase.encode("utf-8"), salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data_str.encode("utf-8"), AES.block_size))
        return base64.b64encode(b"Salted__" + salt + ciphertext).decode("utf-8")

    @staticmethod
    def decrypt(b64_str: str, passphrase: str) -> str:
        data = base64.b64decode(b64_str)
        if data[:8] != b"Salted__":
            return ""
        salt = data[8:16]
        key, iv = evp_kdf(passphrase.encode("utf-8"), salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data[16:]), AES.block_size).decode("utf-8")


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

        dates = await self.get_kv_data(index_key)
        if dates is not None:
            return dates

        # Migrate old data if it exists
        dates = []
        old_data = await self.get_kv_data(old_kv_key)
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
                f"找不到 {date_str} 的日记哦。你可以使用 /查看日记列表 来查看所有已存的日记日期。"
            )

    @filter.command("查看日记本")
    async def webui_diary(self, event: AstrMessageEvent):
        """生成一个精美的跨平台在线日记本网页链接（阅后即焚）"""
        if not MQTT_AVAILABLE:
            yield event.plain_result(
                "服务器缺少 paho-mqtt 或 pycryptodome 扩展，无法生成网页链接。"
            )
            return

        umo = event.unified_msg_origin
        persona_id, _ = await self._get_persona_info(event)

        # 1. 随机生成信道和密钥
        channel_id = generate_random_string(16)
        secret_key = generate_random_string(16)

        # 2. 构造前端链接 (请将这里替换为你实际部署的 Github Pages 链接)
        # 本地测试使用 /diary-webui/index.html 即可，由于用户要直接部署到 github，我们留下占位符
        webui_base_url = self.config.get(
            "webui_url", "https://jingshiro.github.io/dairy_note/"
        )
        if not webui_base_url.endswith("/"):
            webui_base_url += "/"

        full_url = f"{webui_base_url}index.html#channel={channel_id}&key={secret_key}"

        # 3. 启动后台异步任务，监听该信道 5 分钟
        asyncio.create_task(
            self._run_mqtt_client(umo, persona_id, channel_id, secret_key)
        )

        msg = (
            "📖 你的专属日记本链接已生成！\n\n"
            f"{full_url}\n\n"
            "⚠️ 注意：为保障绝对的隐私安全，该链接仅包含你本机的设备解密密钥。云端服务器会在 5 分钟后自动销毁通信频道并断开连接。过期后请重新获取。"
        )
        yield event.plain_result(msg)

    async def _run_mqtt_client(
        self, umo: str, persona_id: str, channel_id: str, secret_key: str
    ):
        """后台运行的一个限时 MQTT 客户端生命周期控制"""
        logger.info(f"[{channel_id}] 开始为 WebUI 创建后台 MQTT 监听信道...")

        up_topic = f"astrbot_diary/{channel_id}/up"
        down_topic = f"astrbot_diary/{channel_id}/down"

        # 使用 paho-mqtt
        client = mqtt.Client(
            client_id=f"astrbot_backend_{channel_id}", transport="websockets"
        )

        # 封装一个跨线程协程调用的事件循环
        loop = asyncio.get_running_loop()

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                logger.info(f"[{channel_id}] MQTT 连接成功，订阅请求频道...")
                client.subscribe(up_topic)
            else:
                logger.error(f"[{channel_id}] MQTT 连接失败: rc={rc}")

        def on_message(client, userdata, msg):
            try:
                payload_str = CryptoJS_AES.decrypt(
                    msg.payload.decode("utf-8"), secret_key
                )
                if not payload_str:
                    return
                payload = json.loads(payload_str)
                action = payload.get("action")

                logger.info(f"[{channel_id}] 收到 WebUI 操作: {action}")

                if action == "ready":
                    asyncio.run_coroutine_threadsafe(
                        self._handle_mqtt_ready(
                            umo, persona_id, client, down_topic, secret_key
                        ),
                        loop,
                    )
                elif action == "delete":
                    date_str = payload.get("date")
                    if date_str:
                        asyncio.run_coroutine_threadsafe(
                            self._handle_mqtt_delete(
                                umo,
                                persona_id,
                                date_str,
                                client,
                                down_topic,
                                secret_key,
                            ),
                            loop,
                        )
            except Exception as e:
                logger.error(f"[{channel_id}] 处理 MQTT 消息失败: {e}")

        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect_async("broker.emqx.io", 8084, 60)
            client.loop_start()

            # 生命周期维持 5 分钟 (300 秒)
            await asyncio.sleep(300)

        except Exception as e:
            logger.error(f"[{channel_id}] MQTT 客户端运行异常: {e}")
        finally:
            logger.info(f"[{channel_id}] WebUI 生命周期结束，正在销毁 MQTT 频道...")
            client.loop_stop()
            client.disconnect()

    async def _handle_mqtt_ready(
        self,
        umo: str,
        persona_id: str,
        client: Any,
        down_topic: str,
        secret_key: str,
    ):
        """处理网页就绪，下发全部日记数据"""
        dates = await self._get_index(umo, persona_id)
        data = []
        for d in dates:
            content_key = f"diary_content_{umo}_{persona_id}_{d}"
            content = await self.get_kv_data(content_key, default="")
            data.append({"date": d, "content": content})

        resp = {"action": "sync", "data": data}
        encrypted_resp = CryptoJS_AES.encrypt(json.dumps(resp), secret_key)
        client.publish(down_topic, encrypted_resp)

    async def _handle_mqtt_delete(
        self,
        umo: str,
        persona_id: str,
        date_str: str,
        client: Any,
        down_topic: str,
        secret_key: str,
    ):
        """处理网页删除请求"""
        success = await self._remove_from_index_or_clear(umo, persona_id, date_str)
        if not success:
            resp = {
                "action": "alert",
                "msg": f"删除失败：未找到 {date_str} 的日记，或发生错误。",
            }
            encrypted_resp = CryptoJS_AES.encrypt(json.dumps(resp), secret_key)
            client.publish(down_topic, encrypted_resp)

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
