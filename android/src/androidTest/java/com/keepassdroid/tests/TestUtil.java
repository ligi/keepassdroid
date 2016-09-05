/*
 * Copyright 2010-2016 Brian Pellin.
 *     
 * This file is part of KeePassDroid.
 *
 *  KeePassDroid is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDroid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.keepassdroid.tests;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;
import com.keepassdroid.utils.EmptyUtils;
import com.keepassdroid.utils.UriUtil;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;

public class TestUtil {

    public static void extractKey(Context ctx, String asset, File target) throws Exception {

        InputStream key = ctx.getAssets().open(asset, AssetManager.ACCESS_STREAMING);

        FileOutputStream keyFile = new FileOutputStream(target);
        while (true) {
            byte[] buf = new byte[1024];
            int read = key.read(buf);
            if (read == -1) {
                break;
            } else {
                keyFile.write(buf, 0, read);
            }
        }

        keyFile.close();

    }

    public static InputStream getKeyFileInputStream(Context ctx, String keyfile) throws FileNotFoundException {
        InputStream keyIs = null;
        if (!EmptyUtils.isNullOrEmpty(keyfile)) {
            Uri uri = UriUtil.parseDefaultFile(keyfile);
            keyIs = UriUtil.getUriInputStream(ctx, uri);
        }

        return keyIs;
    }
}
