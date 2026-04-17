from datetime import datetime
from util import get_date, is_truthy


class TestGetDate:

    def test_unix_timestamp(self):
        result = get_date('1458729615', uts=True)
        assert isinstance(result, datetime)
        assert result == datetime.fromtimestamp(1458729615)

    def test_unix_timestamp_float(self):
        result = get_date('1458729615.5', uts=True)
        assert isinstance(result, datetime)

    def test_text_format(self):
        result = get_date('Wed Mar 23 21:40:15 2016', uts=False)
        assert result.year == 2016
        assert result.month == 3
        assert result.day == 23
        assert result.hour == 21
        assert result.minute == 40
        assert result.second == 15

    def test_text_format_is_default(self):
        result = get_date('Wed Mar 23 21:40:15 2016')
        assert result.year == 2016


class TestIsTruthy:

    def test_true_strings(self):
        assert is_truthy('True') is True
        assert is_truthy('true') is True
        assert is_truthy('Yes') is True
        assert is_truthy('yes') is True

    def test_bool_true(self):
        assert is_truthy(True) is True

    def test_false_strings(self):
        assert is_truthy('False') is False
        assert is_truthy('false') is False
        assert is_truthy('No') is False
        assert is_truthy('no') is False
        assert is_truthy('') is False

    def test_bool_false(self):
        assert is_truthy(False) is False

    def test_none(self):
        assert is_truthy(None) is False

    def test_integer(self):
        # 1 == True in Python (bool is a subclass of int)
        assert is_truthy(1) is True
        assert is_truthy(0) is False
