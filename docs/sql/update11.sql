-- SPDX-FileCopyrightText: 2017 Jan Dorsman
-- SPDX-FileCopyrightText: 2018 Michel Oosterhof <michel@oosterhof.net>
--
-- SPDX-License-Identifier: BSD-3-Clause

ALTER TABLE sensors MODIFY ip VARCHAR(255) NOT NULL;
