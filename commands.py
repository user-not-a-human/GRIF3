"""
Модуль команд для Undo/Redo.

Реализует паттерн Command для операций редактирования диска.
Позволяет отменять и повторять изменения с визуальным журналом.
"""

from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
import struct


class Command(ABC):
    """Базовый класс команды."""

    def __init__(self, description: str):
        self.description = description

    @abstractmethod
    def execute(self) -> None:
        """Выполнить команду."""
        pass

    @abstractmethod
    def undo(self) -> None:
        """Отменить команду."""
        pass


class ReplaceCommand(Command):
    """Команда замены байтов."""

    def __init__(self, reader, offset: int, old_data: bytes, new_data: bytes):
        super().__init__(f"Замена {len(new_data)} байт по смещению 0x{offset:X}")
        self.reader = reader
        self.offset = offset
        self.old_data = old_data
        self.new_data = new_data

    def execute(self) -> None:
        self.reader.write(self.offset, self.new_data)

    def undo(self) -> None:
        self.reader.write(self.offset, self.old_data)


class CommandHistory:
    """История команд с Undo/Redo."""

    def __init__(self):
        self._commands: List[Command] = []
        self._current_index = -1
        self._max_history = 100  # Максимум команд в истории

    def execute(self, command: Command) -> None:
        """Выполнить команду и добавить в историю."""
        command.execute()
        # Удалить команды после текущей позиции
        self._commands = self._commands[:self._current_index + 1]
        self._commands.append(command)
        self._current_index += 1

        # Ограничить размер истории
        if len(self._commands) > self._max_history:
            self._commands.pop(0)
            self._current_index -= 1

    def undo(self) -> Optional[Command]:
        """Отменить последнюю команду."""
        if self.can_undo():
            command = self._commands[self._current_index]
            command.undo()
            self._current_index -= 1
            return command
        return None

    def redo(self) -> Optional[Command]:
        """Повторить отменённую команду."""
        if self.can_redo():
            self._current_index += 1
            command = self._commands[self._current_index]
            command.execute()
            return command
        return None

    def can_undo(self) -> bool:
        return self._current_index >= 0

    def can_redo(self) -> bool:
        return self._current_index < len(self._commands) - 1

    def get_history(self) -> List[str]:
        """Получить список описаний команд для журнала."""
        return [cmd.description for cmd in self._commands]

    def clear(self) -> None:
        """Очистить историю."""
        self._commands.clear()
        self._current_index = -1